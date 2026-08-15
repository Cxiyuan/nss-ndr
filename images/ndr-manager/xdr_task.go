// XDR 分析任务接口：XDR 平台下发检索分析任务，NDR 作为执行者在本地元数据上完成
// 关联分析（后台任务，不向探针用户展示），返回结构化结果供 XDR 编排研判。
//
// 定位（2026-08-15）：NDR = 采集 + 存储 + 上报线索 + 执行 XDR 分析任务；
// XDR = 流程编排与决策（含后续 LLM 研判）。NDR 不承担最终告警决策。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// xdrTaskRequest XDR 下发的分析任务
type xdrTaskRequest struct {
	TaskID        string         `json:"task_id"`
	Target        xdrTaskTarget  `json:"target"`
	WindowSeconds int64          `json:"window_seconds"` // 回溯窗口（秒），默认 3600
	Datasets      []string       `json:"datasets"`       // conn/dns/http/ssl/smb_files/smb_mapping/ntlm/files
	Conditions    map[string]any `json:"conditions,omitempty"`
	GroupBy       string         `json:"group_by,omitempty"` // community_id | src_ip | dst_ip（默认 community_id）
}

type xdrTaskTarget struct {
	CommunityID string `json:"community_id,omitempty"`
	SourceIP    string `json:"src_ip,omitempty"`
	DestIP      string `json:"dst_ip,omitempty"`
	UID         string `json:"uid,omitempty"`
}

// dataset -> ES event.dataset 值
var taskDatasetMap = map[string]string{
	"conn":        "zeek.conn",
	"dns":         "zeek.dns",
	"http":        "zeek.http",
	"ssl":         "zeek.ssl",
	"tls":         "zeek.ssl",
	"smb":         "zeek.smb_files",
	"smb_files":   "zeek.smb_files",
	"smb_mapping": "zeek.smb_mapping",
	"ntlm":        "zeek.ntlm",
	"files":       "zeek.files",
	"ssh":         "zeek.ssh",
}

type taskESClient struct {
	host   string
	auth   string
	client *http.Client
}

func newTaskESClient() *taskESClient {
	host := os.Getenv("ES_HOST")
	if host == "" {
		host = "http://nss-elasticsearch:9200"
	}
	auth := ""
	if u, p := os.Getenv("ES_USERNAME"), os.Getenv("ES_PASSWORD"); u != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
	}
	return &taskESClient{
		host: host,
		auth: auth,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: insecureTLS(),
			},
		},
	}
}

func (c *taskESClient) search(body map[string]any) ([]map[string]any, error) {
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.host+"/logs-zeek-so/_search", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ES 返回 %d: %s", resp.StatusCode, string(raw))
	}
	var sr struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(sr.Hits.Hits))
	for _, h := range sr.Hits.Hits {
		if h.Source != nil {
			out = append(out, h.Source)
		}
	}
	return out, nil
}

// executeXDRTask 在本地元数据上执行关联分析：
// 按目标（community_id/五元组/uid）与时间窗检索指定数据集，按 group_by 聚合返回。
func executeXDRTask(req xdrTaskRequest) (map[string]any, error) {
	if req.TaskID == "" {
		return nil, fmt.Errorf("task_id 不能为空")
	}
	if req.Target.CommunityID == "" && req.Target.SourceIP == "" && req.Target.DestIP == "" && req.Target.UID == "" {
		return nil, fmt.Errorf("target 至少需要 community_id / src_ip / dst_ip / uid 之一")
	}
	window := req.WindowSeconds
	if window <= 0 {
		window = 3600
	}
	now := time.Now().UTC()
	from := now.Add(-time.Duration(window) * time.Second)

	datasets := req.Datasets
	if len(datasets) == 0 {
		datasets = []string{"conn", "dns", "http", "ssl", "smb_files"}
	}

	groupBy := req.GroupBy
	if groupBy == "" {
		groupBy = "community_id"
	}

	client := newTaskESClient()
	result := map[string]any{
		"task_id": req.TaskID,
		"probe_id": func() string {
			if c, err := loadFull(); err == nil {
				return c.Probe.ID
			}
			return ""
		}(),
		"status":   "completed",
		"window":   fmt.Sprintf("%ds", window),
		"from":     from.Format(time.RFC3339),
		"to":       now.Format(time.RFC3339),
		"target":   req.Target,
		"group_by": groupBy,
		"datasets": map[string]any{},
		"summary":  map[string]any{},
	}

	datasetsOut := result["datasets"].(map[string]any)
	summary := result["summary"].(map[string]any)
	totalAll := 0

	for _, ds := range datasets {
		esDS, ok := taskDatasetMap[strings.ToLower(ds)]
		if !ok {
			continue
		}
		filters := []any{
			map[string]any{"term": map[string]any{"event.dataset": esDS}},
			map[string]any{"range": map[string]any{"@timestamp": map[string]any{
				"gte": from.Format(time.RFC3339Nano),
				"lte": now.Format(time.RFC3339Nano),
			}}},
		}
		if req.Target.CommunityID != "" {
			filters = append(filters, map[string]any{"term": map[string]any{"network.community_id": req.Target.CommunityID}})
		}
		if req.Target.SourceIP != "" {
			filters = append(filters, map[string]any{"term": map[string]any{"source.ip": req.Target.SourceIP}})
		}
		if req.Target.DestIP != "" {
			filters = append(filters, map[string]any{"term": map[string]any{"destination.ip": req.Target.DestIP}})
		}
		if req.Target.UID != "" {
			filters = append(filters, map[string]any{"term": map[string]any{"log.id.uid": req.Target.UID}})
		}
		// 附加条件（term/wildcard 简单支持）
		for k, v := range req.Conditions {
			filters = append(filters, map[string]any{"term": map[string]any{k: v}})
		}

		body := map[string]any{
			"size": 200,
			"query": map[string]any{
				"bool": map[string]any{"filter": filters},
			},
			"sort": []any{map[string]any{"@timestamp": map[string]any{"order": "asc"}}},
		}
		hits, err := client.search(body)
		if err != nil {
			// 数据集索引可能尚未产生数据，视为 0 命中
			hits = nil
		}
		events := make([]map[string]any, 0, len(hits))
		for _, h := range hits {
			events = append(events, summarizeTaskEvent(h))
		}
		datasetsOut[ds] = map[string]any{
			"count":  len(events),
			"events": events,
		}
		summary[ds] = len(events)
		totalAll += len(events)
	}
	summary["total"] = totalAll
	return result, nil
}

// summarizeTaskEvent 提取元数据事件关键字段，避免全量原始文档过大
func summarizeTaskEvent(s map[string]any) map[string]any {
	get := func(keys ...string) any {
		var cur any = s
		for _, k := range keys {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = m[k]
		}
		return cur
	}
	out := map[string]any{
		"@timestamp":           get("@timestamp"),
		"event.dataset":        get("event", "dataset"),
		"source.ip":            get("source", "ip"),
		"source.port":          get("source", "port"),
		"destination.ip":       get("destination", "ip"),
		"destination.port":     get("destination", "port"),
		"network.transport":    get("network", "transport"),
		"network.community_id": get("network", "community_id"),
	}
	if v := get("dns", "question", "name"); v != nil {
		out["dns.question.name"] = v
	}
	if v := get("dns", "question", "type"); v != nil {
		out["dns.question.type"] = v
	}
	if v := get("dns", "response_code"); v != nil {
		out["dns.response_code"] = v
	}
	if v := get("dns", "answers"); v != nil {
		out["dns.answers"] = v
	}
	if v := get("url", "full"); v != nil {
		out["url.full"] = v
	}
	if v := get("http", "request", "method"); v != nil {
		out["http.request.method"] = v
	}
	if v := get("http", "response", "status_code"); v != nil {
		out["http.response.status_code"] = v
	}
	if v := get("user_agent", "original"); v != nil {
		out["user_agent.original"] = v
	}
	if v := get("tls", "server", "name"); v != nil {
		out["tls.server.name"] = v
	}
	if v := get("tls", "ja3"); v != nil {
		out["tls.ja3"] = v
	}
	if v := get("smb", "action"); v != nil {
		out["smb.action"] = v
	}
	if v := get("smb", "path"); v != nil {
		out["smb.path"] = v
	}
	if v := get("smb", "name"); v != nil {
		out["smb.name"] = v
	}
	if v := get("smb", "share_type"); v != nil {
		out["smb.share_type"] = v
	}
	if v := get("ntlm", "username"); v != nil {
		out["ntlm.username"] = v
	}
	if v := get("file", "mime_type"); v != nil {
		out["file.mime_type"] = v
	}
	if v := get("file", "name"); v != nil {
		out["file.name"] = v
	}
	if v := get("connection", "state"); v != nil {
		out["connection.state"] = v
	}
	if v := get("event", "duration"); v != nil {
		out["event.duration"] = v
	}
	return out
}

// apiXDRTask XDR 分析任务下发入口（Bearer 令牌认证，非探针用户会话）
func apiXDRTask(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	c, err := loadFull()
	if err != nil || c.Xdr.TaskToken == "" || token != c.Xdr.TaskToken {
		writeErr(w, http.StatusUnauthorized, "XDR 任务令牌无效")
		return
	}
	var req xdrTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	result, err := executeXDRTask(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
