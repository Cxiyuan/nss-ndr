// Sigma 检测调度器：按规则 schedule 定时在 ES 上执行转换后的查询，命中写 logs-detections.alerts-so
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var esSigmaClient *esClient

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
		return nil, fmt.Errorf("ES %s %s: %d %s", method, path, resp.StatusCode, string(data))
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
	for _, r := range enabledSigmaRules() {
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
			log.Printf("warn: sigma 规则 %s 执行失败: %v", r.ID, err)
		}
		_, _ = db.Exec("UPDATE sigma_rules SET last_run_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), r.ID)
	}
}

func executeSigmaRule(r SigmaRule, window time.Duration) error {
	sq, err := buildSigmaQuery(r.Content)
	if err != nil {
		return err
	}
	if len(sq.Indexes) == 0 {
		return fmt.Errorf("规则未匹配任何索引")
	}
	now := time.Now().UTC()
	from := now.Add(-window)
	filters := []any{
		map[string]any{"range": map[string]any{"@timestamp": map[string]any{
			"gte": from.Format(time.RFC3339Nano),
			"lte": now.Format(time.RFC3339Nano),
		}}},
	}
	if sq.Filter != nil {
		filters = append(filters, sq.Filter)
	}
	filters = append(filters, sq.Query)
	body := map[string]any{
		"size": 100,
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
		"sort": []any{map[string]any{"@timestamp": map[string]any{"order": "desc"}}},
	}
	data, err := esSigmaClient.do(http.MethodPost,
		"/"+strings.Join(sq.Indexes, ",")+"/_search", body)
	if err != nil {
		return err
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	if len(resp.Hits.Hits) == 0 {
		return nil
	}
	log.Printf("sigma: 规则 %s(%s) 命中 %d 条", r.ID, r.Title, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		if err := writeSigmaAlert(r, h.Source); err != nil {
			log.Printf("warn: sigma 告警写入失败: %v", err)
		}
	}
	audit("sigma.hit", r.ID, fmt.Sprintf("%s 命中 %d 条", r.Title, len(resp.Hits.Hits)))
	return nil
}

// writeSigmaAlert 构造告警写入 logs-detections.alerts-so（payload 对齐 SO）
func writeSigmaAlert(r SigmaRule, eventData map[string]any) error {
	payload := map[string]any{
		"@timestamp":  time.Now().UTC().Format(time.RFC3339),
		"tags":        "alert",
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
