// Sigma 检测调度器：普通规则定时在 ES 上执行；关联规则走两阶段引擎
// （线索 suricata.alert → 按 group_by 联动 zeek 元数据确认 → 写入最终告警）。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var esSigmaClient *esClient

// sigmaBackoffUntil / sigmaFailStreak：ES 连续不可用时指数退避，避免日志风暴
var (
	sigmaBackoffUntil time.Time
	sigmaFailStreak   int
)

// esHTTPError 携带 HTTP 状态码，便于调用方做容错（如索引未创建时的 404）
type esHTTPError struct {
	method string
	path   string
	code   int
	body   string
}

func (e *esHTTPError) Error() string {
	return fmt.Sprintf("ES %s %s: %d %s", e.method, e.path, e.code, e.body)
}

type esClient struct {
	host   string
	user   string
	pass   string
	client *http.Client
}

func init() {
	esSigmaClient = &esClient{
		host: os.Getenv("ES_HOST"),
		user: os.Getenv("ES_USERNAME"),
		pass: os.Getenv("ES_PASSWORD"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: insecureTLS(),
			},
		},
	}
	if esSigmaClient.host == "" {
		esSigmaClient.host = "http://nss-elasticsearch:9200"
	}
}

func (c *esClient) do(method, path string, body any) ([]byte, error) {
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.host+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, &esHTTPError{method: method, path: path, code: resp.StatusCode, body: string(data)}
	}
	return data, nil
}

// startSigmaScheduler 启动检测调度 goroutine
func startSigmaScheduler() {
	go func() {
		// 启动后立即跑一轮，之后每 30s 检查
		runDueSigmaRules()
		tick := time.NewTicker(30 * time.Second)
		for range tick.C {
			runDueSigmaRules()
		}
	}()
}

func runDueSigmaRules() {
	if time.Now().Before(sigmaBackoffUntil) {
		return
	}
	rules := enabledSigmaRules()
	if len(rules) == 0 {
		return
	}
	failed := 0
	for _, r := range rules {
		interval := parseInterval(r.Schedule)
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		if r.LastRunAt != "" {
			t, err := time.Parse(time.RFC3339, r.LastRunAt)
			if err == nil && time.Since(t) < interval {
				continue
			}
		}
		if err := executeSigmaRule(r, interval); err != nil {
			failed++
			log.Printf("warn: sigma 规则 %s 执行失败: %v", r.ID, err)
		}
		_, _ = db.Exec("UPDATE sigma_rules SET last_run_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), r.ID)
	}
	// 全部规则同时失败说明 ES/调度依赖不可用，指数退避（30s -> 1m -> 2m -> 4m -> 8m，上限 8m）
	if failed == len(rules) && failed > 0 {
		sigmaFailStreak++
		backoff := time.Duration(1<<uint(sigmaFailStreak-1)) * 30 * time.Second
		if backoff > 8*time.Minute {
			backoff = 8 * time.Minute
		}
		sigmaBackoffUntil = time.Now().Add(backoff)
		log.Printf("warn: sigma 调度连续失败 %d 次，退避 %v 后重试", sigmaFailStreak, backoff)
	} else {
		sigmaFailStreak = 0
	}
}

// executeSigmaRule 执行单条规则：普通规则直接查询；关联规则走两阶段关联引擎
func executeSigmaRule(r SigmaRule, window time.Duration) error {
	sy, err := parseSigma(r.Content)
	if err != nil {
		return err
	}
	if sy.Correlation != nil {
		if ts := parseInterval(sy.Correlation.Timespan); ts > 0 {
			window = ts
		}
		alertPolicy := "strict"
		if c, err := loadFull(); err == nil && c.Detections.AlertPolicy != "" {
			alertPolicy = c.Detections.AlertPolicy
		}
		matches, err := executeCorrelationRule(r, sy.Correlation, window, false, alertPolicy)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return nil
		}
		log.Printf("sigma: 关联规则 %s(%s) 命中 %d 组", r.ID, r.Title, len(matches))
		written := 0
		for _, m := range matches {
			if err := writeSigmaCorrelationAlert(r, sy.Correlation, m); err != nil {
				log.Printf("warn: sigma 关联告警写入失败: %v", err)
				continue
			}
			written++
		}
		audit("sigma.hit", r.ID, fmt.Sprintf("%s 关联命中 %d 组（写入 %d 条告警）", r.Title, len(matches), written))
		return nil
	}

	sq, err := buildSigmaQuery(r.Content)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	from := now.Add(-window)
	var hits []map[string]any
	if sq.Backend == "esql" && sq.ESQL != "" {
		hits, err = runEsqlQuery(sq, from, now)
		if err != nil {
			log.Printf("warn: sigma 规则 %s ES|QL 执行失败，回退 EQL: %v", r.ID, err)
			hits, err = runSigmaQuery(sq, from, now, nil)
		}
	} else {
		hits, err = runSigmaQuery(sq, from, now, nil)
	}
	if err != nil {
		return err
	}
	if len(hits) == 0 {
		return nil
	}
	log.Printf("sigma: 规则 %s(%s) 命中 %d 条", r.ID, r.Title, len(hits))
	written := 0
	for _, h := range hits {
		if err := writeSigmaAlert(r, h); err != nil {
			log.Printf("warn: sigma 告警写入失败: %v", err)
			continue
		}
		written++
	}
	audit("sigma.hit", r.ID, fmt.Sprintf("%s 命中 %d 条（写入 %d 条告警）", r.Title, len(hits), written))
	return nil
}

// runSigmaQuery 执行 EQL 查询，返回命中的原始文档（_source）
func runSigmaQuery(sq *sigmaQuery, from, to time.Time, keyFilter map[string]any) ([]map[string]any, error) {
	if len(sq.Indexes) == 0 {
		return nil, fmt.Errorf("规则未匹配任何索引")
	}
	filter := map[string]any{"range": map[string]any{"@timestamp": map[string]any{
		"gte": from.Format(time.RFC3339Nano),
		"lte": to.Format(time.RFC3339Nano),
	}}}
	if keyFilter != nil {
		filter = map[string]any{"bool": map[string]any{"filter": []any{
			filter,
			map[string]any{"terms": keyFilter},
		}}}
	}
	body := map[string]any{
		"query":  sq.EQL,
		"filter": filter,
		"size":   100,
	}
	data, err := esSigmaClient.do(http.MethodPost,
		"/"+strings.Join(sq.Indexes, ",")+"/_eql/search", body)
	if err != nil {
		var he *esHTTPError
		if errors.As(err, &he) && he.code == http.StatusNotFound {
			// 索引尚未创建（如新部署尚无告警/元数据）：视为无命中，不报错
			return nil, nil
		}
		return nil, err
	}
	var resp struct {
		Hits struct {
			Events []struct {
				Source map[string]any `json:"_source"`
			} `json:"events"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(resp.Hits.Events))
	for _, h := range resp.Hits.Events {
		if h.Source != nil {
			out = append(out, h.Source)
		}
	}
	return out, nil
}

// runEsqlQuery 通过 ES|QL _query API 执行查询（backend=esql 时使用）。
// 注意：ES|QL 返回扁平列而非 _source，证据字段会以列名（可能带点号）平铺。
func runEsqlQuery(sq *sigmaQuery, from, to time.Time) ([]map[string]any, error) {
	body := map[string]any{
		"query": sq.ESQL,
		"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{
			"gte": from.Format(time.RFC3339Nano),
			"lte": to.Format(time.RFC3339Nano),
		}}},
	}
	data, err := esSigmaClient.do(http.MethodPost, "/_query?format=json", body)
	if err != nil {
		var he *esHTTPError
		if errors.As(err, &he) && he.code == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var resp struct {
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
		Values [][]any `json:"values"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(resp.Values))
	for _, row := range resp.Values {
		doc := map[string]any{}
		for i, col := range resp.Columns {
			if i < len(row) {
				doc[col.Name] = row[i]
			}
		}
		out = append(out, doc)
	}
	return out, nil
}

// correlationMatch 一组关联命中的证据（一个 group_by 键）
type correlationMatch struct {
	Key         string           `json:"key"`
	ClueHits    []map[string]any `json:"clue_hits"`
	ConfirmHits []map[string]any `json:"confirm_hits"`
	Confirmed   bool             `json:"confirmed"`
}

// executeCorrelationRule 两阶段关联引擎：
//
//	required=both   -> 线索与确认按 group_by 键求交，仅交集的键出告警；
//	                   fallback=clue_only/confirm_only 时未确认的键按降置信度出告警
//	required=clue   -> 只要线索命中即告警（confirm 命中作为加分证据）
//	required=confirm-> 仅确认条件命中即告警（Zeek-only 场景）
//
// dryRun=true 时不写 ES 告警，供证据预览接口使用。
// allowFallback 是否允许"未确认回退"输出：strict 策略下仅输出确认告警
func allowFallback(alertPolicy, fallback string) bool {
	return alertPolicy != "strict" && fallback != ""
}

func executeCorrelationRule(r SigmaRule, corr *sigmaCorrelation, window time.Duration, dryRun bool, alertPolicy string) ([]correlationMatch, error) {
	groupBy := corr.GroupBy
	if groupBy == "" {
		groupBy = "network.community_id"
	}
	now := time.Now().UTC()
	from := now.Add(-window)

	var clueHits []map[string]any
	if corr.Clue != nil {
		sq, err := buildStageQuery(*corr.Clue, r.Title, r.ID)
		if err != nil {
			return nil, fmt.Errorf("线索查询转换失败: %w", err)
		}
		clueHits, err = runSigmaQuery(sq, from, now, nil)
		if err != nil {
			return nil, fmt.Errorf("线索查询执行失败: %w", err)
		}
	}
	clueKeys := groupHitsByKey(clueHits, groupBy)

	var confirmHits []map[string]any
	if corr.Confirm != nil {
		sq, err := buildStageQuery(*corr.Confirm, r.Title, r.ID)
		if err != nil {
			return nil, fmt.Errorf("确认查询转换失败: %w", err)
		}
		var keyFilter map[string]any
		if corr.Required == "both" && len(clueKeys) > 0 {
			keys := make([]string, 0, len(clueKeys))
			for k := range clueKeys {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 500 {
				keys = keys[:500]
			}
			keyFilter = map[string]any{groupBy: keys}
		}
		confirmHits, err = runSigmaQuery(sq, from, now, keyFilter)
		if err != nil {
			return nil, fmt.Errorf("确认查询执行失败: %w", err)
		}
	}
	confirmKeys := groupHitsByKey(confirmHits, groupBy)

	matches := []correlationMatch{}
	switch corr.Required {
	case "clue":
		for key, hs := range clueKeys {
			m := correlationMatch{Key: key, ClueHits: hs}
			if _, ok := confirmKeys[key]; ok {
				m.Confirmed = true
			}
			matches = append(matches, m)
		}
	case "confirm":
		for key, hs := range confirmKeys {
			matches = append(matches, correlationMatch{Key: key, ConfirmHits: hs, Confirmed: true})
		}
	default: // both
		for key, hs := range clueKeys {
			if ch, ok := confirmKeys[key]; ok {
				matches = append(matches, correlationMatch{Key: key, ClueHits: hs, ConfirmHits: ch, Confirmed: true})
			} else if allowFallback(alertPolicy, corr.Fallback) && corr.Fallback == "clue_only" {
				matches = append(matches, correlationMatch{Key: key, ClueHits: hs, Confirmed: false})
			}
		}
		if allowFallback(alertPolicy, corr.Fallback) && corr.Fallback == "confirm_only" {
			for key, ch := range confirmKeys {
				if _, ok := clueKeys[key]; !ok {
					matches = append(matches, correlationMatch{Key: key, ConfirmHits: ch, Confirmed: false})
				}
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Key < matches[j].Key })
	if len(matches) > 50 {
		matches = matches[:50]
	}
	for i := range matches {
		matches[i].ClueHits = summarizeHits(matches[i].ClueHits)
		matches[i].ConfirmHits = summarizeHits(matches[i].ConfirmHits)
	}
	return matches, nil
}

func groupHitsByKey(hits []map[string]any, key string) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, h := range hits {
		k := extractField(h, key)
		out[k] = append(out[k], h)
	}
	return out
}

// extractField 按点号路径提取字段值（如 network.community_id）
func extractField(src map[string]any, dotted string) string {
	if dotted == "" {
		return ""
	}
	var cur any = src
	for _, part := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[part]
	}
	switch v := cur.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// sigmaEvidenceFields 是告警证据保留的字段白名单（控制告警体积，保留分析上下文）
var sigmaEvidenceFields = []string{
	"@timestamp", "event", "source", "destination", "network", "observer",
	"dns", "http", "tls", "url", "server", "rule", "message", "uid", "nss",
}

func summarizeHits(hits []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		m := map[string]any{}
		for _, f := range sigmaEvidenceFields {
			if v, ok := h[f]; ok {
				m[f] = v
			}
		}
		if len(m) == 0 {
			m = h // 兜底：无白名单字段时保留原文，避免丢证据
		}
		out = append(out, m)
	}
	return out
}

func firstHit(hits []map[string]any) map[string]any {
	if len(hits) == 0 {
		return nil
	}
	return hits[0]
}

// writeSigmaCorrelationAlert 构造关联告警写入 logs-detections.alerts-so
// （证据字段放 nss.correlation，event_data 兼容 xdr-push 推送）
func writeSigmaCorrelationAlert(r SigmaRule, corr *sigmaCorrelation, m correlationMatch) error {
	confidence := corr.Confidence
	// 仅 required=both 且未确认的回退告警降级；required=clue 直接告警保持声明置信度
	if corr.Required == "both" && !m.Confirmed {
		// 回退告警：置信度降级为 low
		confidence = "low"
	}
	payload := map[string]any{
		"@timestamp": time.Now().UTC().Format(time.RFC3339),
		"tags":       "alert",
		"rule": map[string]any{
			"name":       r.Title,
			"uuid":       r.ID,
			"category":   r.Category,
			"product":    r.Product,
			"service":    r.Service,
			"type":       "correlation",
			"confidence": confidence,
		},
		"event": map[string]any{
			"severity":       confidence,
			"severity_label": confidence,
			"module":         "sigma",
			"dataset":        "detections.alerts",
		},
		"sigma_level": r.Level,
		"nss": map[string]any{
			"correlation": map[string]any{
				"type":         "correlation",
				"required":     corr.Required,
				"fallback":     corr.Fallback,
				"confidence":   confidence,
				"confirmed":    m.Confirmed,
				"group_by":     corr.GroupBy,
				"key":          m.Key,
				"clue_hits":    m.ClueHits,
				"confirm_hits": m.ConfirmHits,
			},
		},
	}
	if ed := firstHit(m.ClueHits); ed != nil {
		payload["event_data"] = ed
	} else if ed := firstHit(m.ConfirmHits); ed != nil {
		payload["event_data"] = ed
	}
	_, err := esSigmaClient.do(http.MethodPost,
		"/logs-detections.alerts-so/_doc?pipeline=detections.alert", payload)
	return err
}

// writeSigmaAlert 构造普通规则告警写入 logs-detections.alerts-so（payload 对齐 SO）
func writeSigmaAlert(r SigmaRule, eventData map[string]any) error {
	payload := map[string]any{
		"@timestamp": time.Now().UTC().Format(time.RFC3339),
		"tags":       "alert",
		"rule": map[string]any{
			"name":     r.Title,
			"uuid":     r.ID,
			"category": r.Category,
			"product":  r.Product,
			"service":  r.Service,
		},
		"event": map[string]any{
			"severity":       r.Level,
			"module":         "sigma",
			"dataset":        "detections.alerts",
			"severity_label": r.Level,
		},
		"sigma_level": r.Level,
		"event_data":  eventData,
	}
	if _, err := esSigmaClient.do(http.MethodPost,
		"/logs-detections.alerts-so/_doc?pipeline=detections.alert", payload); err != nil {
		return err
	}
	return nil
}

func parseInterval(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	unit := "m"
	if len(s) >= 2 {
		last := s[len(s)-1]
		if last == 's' || last == 'm' || last == 'h' {
			unit = string(last)
			s = s[:len(s)-1]
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0
	}
	switch unit {
	case "s":
		return time.Duration(n) * time.Second
	case "h":
		return time.Duration(n) * time.Hour
	default:
		return time.Duration(n) * time.Minute
	}
}
