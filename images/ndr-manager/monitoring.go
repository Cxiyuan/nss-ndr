// NDR 运维监控可视化（仅本系统自身运维指标，不展示具体安全事件内容）
//
// 提供 4 个端点：
//   GET /api/monitoring/traffic        最近 60 分钟流量波形（zeek.conn，每分钟 eps + bps）
//   GET /api/monitoring/workload       当日工作量统计（事件总量 / 线索量 / Strelka 文件数 / XDR 推送计数）
//   GET /api/monitoring/health         系统健康（组件 / ES / 磁盘 / cleaner）
//   GET /api/monitoring/alerts-today   今日线索分时柱状图（按小时）
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ---- XDR 推送运行时计数（自启动以来；DLQ 条数另从 state 文件读取）----
var (
	xdrPushSuccessCount int64
	xdrPushFailedCount  int64
	xdrPushLastSuccess  atomic.Value // time.Time
	xdrPushLastFailed   atomic.Value // time.Time
)

func recordXdrPushSuccess() {
	atomic.AddInt64(&xdrPushSuccessCount, 1)
	xdrPushLastSuccess.Store(time.Now().UTC())
}

func recordXdrPushFailed() {
	atomic.AddInt64(&xdrPushFailedCount, 1)
	xdrPushLastFailed.Store(time.Now().UTC())
}

// ---- 响应结构 ----

type trafficSample struct {
	Ts  time.Time `json:"ts"`
	Eps float64   `json:"eps"` // events per second（连接事件近似）
	Bps float64   `json:"bps"` // bytes per second
}

type trafficResp struct {
	Samples []trafficSample `json:"samples"`
}

type datasetCount struct {
	Dataset string `json:"dataset"`
	Count   int64  `json:"count"`
}

type workloadResp struct {
	TotalEventsToday  int64          `json:"total_events_today"`
	EventsByDataset   []datasetCount `json:"events_by_dataset"`
	AlertsToday       int64          `json:"alerts_today"`
	StrelkaFilesToday int64          `json:"strelka_files_today"`
	XdrPush           xdrPushStats   `json:"xdr_push"`
	GeneratedAt       time.Time      `json:"generated_at"`
	ESError           string         `json:"es_error,omitempty"`
}

type xdrPushStats struct {
	Success     int64      `json:"success"`
	Failed      int64      `json:"failed"`
	DLQ         int64      `json:"dlq"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastFailed  *time.Time `json:"last_failed,omitempty"`
}

type componentHealth struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type esHealth struct {
	Status string `json:"status"`
	Nodes  int    `json:"nodes"`
	Error  string `json:"error,omitempty"`
}

type diskUsage struct {
	Mount    string  `json:"mount"`
	UsagePct int     `json:"usage_pct"`
	FreeGB   float64 `json:"free_gb"`
}

type cleanerStatusView struct {
	LastRun          string `json:"last_run,omitempty"`
	RemovedFiles     int    `json:"removed_files"`
	RemovedBytes     int64  `json:"removed_bytes"`
	PressureTriggered bool  `json:"pressure_triggered"`
	FSUsagePct       int    `json:"fs_usage_pct"`
	Error            string `json:"error,omitempty"`
}

type healthResp struct {
	Components  []componentHealth `json:"components"`
	ES          esHealth          `json:"es"`
	Disk        []diskUsage       `json:"disk"`
	Cleaner     cleanerStatusView `json:"cleaner"`
	GeneratedAt time.Time         `json:"generated_at"`
}

type alertBucket struct {
	Hour  string `json:"hour"`
	Count int64  `json:"count"`
}

type alertsTodayResp struct {
	Buckets     []alertBucket `json:"buckets"`
	Total       int64         `json:"total"`
	GeneratedAt time.Time     `json:"generated_at"`
	ESError     string        `json:"es_error,omitempty"`
}

// ---- ES 客户端 ----

type monitoringESClient struct {
	host   string
	auth   string
	client *http.Client
}

func newMonitoringESClient() *monitoringESClient {
	host := os.Getenv("ES_HOST")
	if host == "" {
		host = "http://nss-elasticsearch:9200"
	}
	auth := ""
	if u, p := os.Getenv("ES_USERNAME"), os.Getenv("ES_PASSWORD"); u != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
	}
	return &monitoringESClient{
		host:   host,
		auth:   auth,
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: insecureTLS()}},
	}
}

// search 对指定 index（或全部，index=""）执行 _search；返回原始响应字节
func (c *monitoringESClient) search(index string, body map[string]any) ([]byte, error) {
	path := "/_search"
	if index != "" {
		path = "/" + index + "/_search"
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.host+path, bytes.NewReader(data))
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
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ES 返回 %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}

func (c *monitoringESClient) count(index string, body map[string]any) (int64, error) {
	path := "/" + index + "/_count"
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.host+path, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("ES 返回 %d: %s", resp.StatusCode, string(b))
	}
	var cr struct {
		Count int64 `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return 0, err
	}
	return cr.Count, nil
}

// ---- API handlers ----

// apiMonitoringTraffic 最近 60 分钟流量波形（zeek.conn）
func apiMonitoringTraffic(w http.ResponseWriter, _ *http.Request) {
	cli := newMonitoringESClient()
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{"filter": []any{
				map[string]any{"term": map[string]any{"event.dataset": "zeek.conn"}},
				map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-60m"}}},
			}},
		},
		"aggs": map[string]any{
			"per_minute": map[string]any{
				"date_histogram": map[string]any{
					"field":          "@timestamp",
					"fixed_interval": "1m",
					"min_doc_count":  0,
				},
				"aggs": map[string]any{
					"bytes_sum": map[string]any{"sum": map[string]any{"field": "network.bytes"}},
				},
			},
		},
	}
	raw, err := cli.search("logs-zeek-so", body)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "ES 查询失败: "+err.Error())
		return
	}
	var sr struct {
		Aggregations struct {
			PerMinute struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					DocCount    int64  `json:"doc_count"`
					BytesSum    struct {
						Value float64 `json:"value"`
					} `json:"bytes_sum"`
				} `json:"buckets"`
			} `json:"per_minute"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	samples := make([]trafficSample, 0, len(sr.Aggregations.PerMinute.Buckets))
	for _, b := range sr.Aggregations.PerMinute.Buckets {
		ts, _ := time.Parse(time.RFC3339, b.KeyAsString)
		samples = append(samples, trafficSample{
			Ts:  ts,
			Eps: float64(b.DocCount) / 60.0,
			Bps: b.BytesSum.Value / 60.0,
		})
	}
	writeJSON(w, http.StatusOK, trafficResp{Samples: samples})
}

// apiMonitoringWorkload 当日工作量统计
func apiMonitoringWorkload(w http.ResponseWriter, _ *http.Request) {
	cli := newMonitoringESClient()
	out := workloadResp{GeneratedAt: time.Now().UTC()}

	// 1) 当日事件总量 + 按 dataset 分布
	body1 := map[string]any{
		"size": 0,
		"query": map[string]any{
			"range": map[string]any{"@timestamp": map[string]any{"gte": "now-24h"}},
		},
		"aggs": map[string]any{
			"by_dataset": map[string]any{
				"terms": map[string]any{"field": "event.dataset", "size": 20},
			},
		},
	}
	raw1, err := cli.search("logs-zeek-so,logs-suricata.alerts-so,logs-strelka-so", body1)
	if err != nil {
		out.ESError = "事件聚合失败: " + err.Error()
	} else {
		var sr1 struct {
			Hits struct {
				Total struct {
					Value int64 `json:"value"`
				} `json:"total"`
			} `json:"hits"`
			Aggregations struct {
				ByDataset struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int64  `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_dataset"`
			} `json:"aggregations"`
		}
		if json.Unmarshal(raw1, &sr1) == nil {
			out.TotalEventsToday = sr1.Hits.Total.Value
			for _, b := range sr1.Aggregations.ByDataset.Buckets {
				out.EventsByDataset = append(out.EventsByDataset, datasetCount{Dataset: b.Key, Count: b.DocCount})
			}
			sort.Slice(out.EventsByDataset, func(i, j int) bool {
				return out.EventsByDataset[i].Count > out.EventsByDataset[j].Count
			})
		}
	}

	// 2) 当日 Suricata 告警线索量（logs-suricata.alerts-so）
	countBody := map[string]any{
		"query": map[string]any{
			"range": map[string]any{"@timestamp": map[string]any{"gte": "now-24h"}},
		},
	}
	if n, err := cli.count("logs-suricata.alerts-so", countBody); err != nil {
		if out.ESError == "" {
			out.ESError = "线索计数失败: " + err.Error()
		}
	} else {
		out.AlertsToday = n
	}

	// 3) 当日 Strelka 处理文件数（logs-strelka-so）
	if n, err := cli.count("logs-strelka-so", countBody); err == nil {
		out.StrelkaFilesToday = n
	}

	// 4) XDR 推送计数（in-memory 累计 + DLQ 文件行数）
	stats := xdrPushStats{
		Success: atomic.LoadInt64(&xdrPushSuccessCount),
		Failed:  atomic.LoadInt64(&xdrPushFailedCount),
		DLQ:     countDLQLines(),
	}
	if v := xdrPushLastSuccess.Load(); v != nil {
		t := v.(time.Time)
		stats.LastSuccess = &t
	}
	if v := xdrPushLastFailed.Load(); v != nil {
		t := v.(time.Time)
		stats.LastFailed = &t
	}
	out.XdrPush = stats

	writeJSON(w, http.StatusOK, out)
}

// apiMonitoringHealth 系统健康
func apiMonitoringHealth(w http.ResponseWriter, _ *http.Request) {
	out := healthResp{
		GeneratedAt: time.Now().UTC(),
		Components:  getDockerComponents(),
		ES:          getESHealth(),
		Disk:        getDiskUsage(),
		Cleaner:     getCleanerStatus(),
	}
	writeJSON(w, http.StatusOK, out)
}

// apiMonitoringAlertsToday 今日线索分时柱状图
func apiMonitoringAlertsToday(w http.ResponseWriter, _ *http.Request) {
	cli := newMonitoringESClient()
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"range": map[string]any{"@timestamp": map[string]any{"gte": "now-24h"}},
		},
		"aggs": map[string]any{
			"per_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":          "@timestamp",
					"fixed_interval": "1h",
				},
			},
		},
	}
	raw, err := cli.search("logs-suricata.alerts-so", body)
	if err != nil {
		writeJSON(w, http.StatusOK, alertsTodayResp{
			GeneratedAt: time.Now().UTC(),
			ESError:     err.Error(),
		})
		return
	}
	var sr struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			PerHour struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					DocCount    int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"per_hour"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := alertsTodayResp{
		Total:       sr.Hits.Total.Value,
		GeneratedAt: time.Now().UTC(),
	}
	for _, b := range sr.Aggregations.PerHour.Buckets {
		out.Buckets = append(out.Buckets, alertBucket{Hour: b.KeyAsString, Count: b.DocCount})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- 辅助函数 ----

func countDLQLines() int64 {
	path := filepath.Join(stateDir, "xdr-push-dlq.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return int64(bytes.Count(data, []byte("\n")))
}

// getDockerComponents 列出 nss-* 容器的状态（不依赖 compose dir；docker ps 全局可见即可）
func getDockerComponents() []componentHealth {
	out := []componentHealth{}
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}")
	stdout, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.HasPrefix(parts[0], "nss-") {
			continue
		}
		out = append(out, componentHealth{Name: parts[0], State: parts[1]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func getESHealth() esHealth {
	cli := newMonitoringESClient()
	req, err := http.NewRequest(http.MethodGet, cli.host+"/_cluster/health", nil)
	if err != nil {
		return esHealth{Status: "error", Error: err.Error()}
	}
	if cli.auth != "" {
		req.Header.Set("Authorization", cli.auth)
	}
	resp, err := cli.client.Do(req)
	if err != nil {
		return esHealth{Status: "unreachable", Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return esHealth{Status: "error", Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	var h struct {
		Status         string `json:"status"`
		NumberOfNodes  int    `json:"number_of_nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return esHealth{Status: "error", Error: err.Error()}
	}
	return esHealth{Status: h.Status, Nodes: h.NumberOfNodes}
}

func getDiskUsage() []diskUsage {
	out := []diskUsage{}
	dirs := []string{"/nsm", "/opt/ndr"}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		cmd := exec.Command("df", "-P", dir)
		stdout, err := cmd.Output()
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
		if len(lines) < 2 {
			continue
		}
		fields := strings.Fields(lines[len(lines)-1])
		if len(fields) < 5 {
			continue
		}
		pct, _ := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		avail, _ := strconv.ParseInt(fields[3], 10, 64)
		out = append(out, diskUsage{
			Mount:    dir,
			UsagePct: pct,
			FreeGB:   float64(avail) / 1e9,
		})
	}
	return out
}

func getCleanerStatus() cleanerStatusView {
	path := filepath.Join(stateDir, "cleaner-status.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return cleanerStatusView{Error: "未运行或尚未产出状态文件"}
	}
	var raw struct {
		Time              string `json:"time"`
		FSUsagePct        int    `json:"fs_usage_pct"`
		PressureTriggered bool   `json:"pressure_triggered"`
		RemovedFiles      int    `json:"removed_files"`
		RemovedBytes      int64  `json:"removed_bytes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return cleanerStatusView{Error: "状态文件解析失败: " + err.Error()}
	}
	return cleanerStatusView{
		LastRun:           raw.Time,
		FSUsagePct:        raw.FSUsagePct,
		PressureTriggered: raw.PressureTriggered,
		RemovedFiles:      raw.RemovedFiles,
		RemovedBytes:      raw.RemovedBytes,
	}
}