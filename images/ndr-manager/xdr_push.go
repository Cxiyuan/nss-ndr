// 线索上报（原 xdr-push 镜像功能并入 manager）：定时从 ES 拉取检测线索
// （suricata.alert），推送到 XDR Webhook（HMAC 签名 + 重试 + 死信 + 游标断点续传）。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type xdrPushConfig struct {
	XDR struct {
		Webhook struct {
			URL    string `yaml:"url"`
			Secret string `yaml:"secret"`
		} `yaml:"webhook"`
		TimeoutS      int      `yaml:"timeout_s"`
		PushIntervalS int      `yaml:"push_interval_s"`
		RetryMax      int      `yaml:"retry_max"`
		EventTypes    []string `yaml:"event_types"`
	} `yaml:"xdr"`
	Probe struct {
		ID string `yaml:"id"`
	} `yaml:"probe"`
}

type xdrCursor struct {
	TS       int64 `json:"ts"`
	ShardDoc int64 `json:"shard_doc"`
}

type xdrHit struct {
	ID     string         `json:"_id"`
	Source map[string]any `json:"_source"`
	Sort   []any          `json:"sort"`
}

type xdrPoller struct {
	host   string
	client *http.Client
	types  []string
	auth   string
}

func newXdrPoller() *xdrPoller {
	host := os.Getenv("ES_HOST")
	if host == "" {
		host = "http://nss-elasticsearch:9200"
	}
	auth := ""
	if u, p := os.Getenv("ES_USERNAME"), os.Getenv("ES_PASSWORD"); u != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
	}
	cfg := loadXdrPushConfig()
	return &xdrPoller{
		host:   host,
		types:  cfg.XDR.EventTypes,
		auth:   auth,
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: insecureTLS()}},
	}
}

func (p *xdrPoller) Fetch(c xdrCursor) ([]xdrHit, *xdrCursor, error) {
	should := make([]map[string]any, 0, len(p.types))
	for _, t := range p.types {
		should = append(should, map[string]any{"term": map[string]any{"event.dataset": t}})
	}
	body := map[string]any{
		"size": 100,
		"query": map[string]any{
			"bool": map[string]any{"should": should, "minimum_should_match": 1},
		},
		"sort": []any{
			map[string]any{"@timestamp": map[string]any{"order": "asc", "unmapped_type": "long"}},
			map[string]any{"_shard_doc": map[string]any{"order": "asc"}},
		},
	}
	if c.TS != 0 {
		body["search_after"] = []any{c.TS, c.ShardDoc}
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/logs-suricata.alerts-so/_search", p.host), bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.auth != "" {
		req.Header.Set("Authorization", p.auth)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("ES 返回 %d: %s", resp.StatusCode, string(b))
	}
	var sr struct {
		Hits struct {
			Hits []xdrHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, nil, err
	}
	if len(sr.Hits.Hits) == 0 {
		return nil, nil, nil
	}
	last := sr.Hits.Hits[len(sr.Hits.Hits)-1]
	var next *xdrCursor
	if len(last.Sort) == 2 {
		ts, _ := last.Sort[0].(float64)
		sd, _ := last.Sort[1].(float64)
		next = &xdrCursor{TS: int64(ts), ShardDoc: int64(sd)}
	}
	return sr.Hits.Hits, next, nil
}

type xdrWebhookClient struct {
	cfg    xdrPushConfig
	client *http.Client
}

func (w *xdrWebhookClient) Push(h xdrHit) error {
	payload := xdrBuildPayload(h, w.cfg.Probe.ID)
	body, _ := json.Marshal(payload)
	var lastErr error
	for attempt := 1; attempt <= w.cfg.XDR.RetryMax; attempt++ {
		req, err := http.NewRequest(http.MethodPost, w.cfg.XDR.Webhook.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if w.cfg.XDR.Webhook.Secret != "" {
			req.Header.Set("X-NDR-Signature", xdrSign(body, w.cfg.XDR.Webhook.Secret))
		}
		resp, err := w.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				recordXdrPushSuccess()
				return nil
			}
			lastErr = fmt.Errorf("webhook 返回 %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt*attempt) * time.Second)
	}
	recordXdrPushFailed()
	return fmt.Errorf("重试 %d 次仍失败: %w", w.cfg.XDR.RetryMax, lastErr)
}

func xdrSign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func xdrBuildPayload(h xdrHit, probeID string) map[string]any {
	src := h.Source
	get := func(keys ...string) any {
		var cur any = src
		for _, k := range keys {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = m[k]
		}
		return cur
	}
	ts, _ := get("@timestamp").(string)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	ev, _ := get("event").(map[string]any)
	netw, _ := get("network").(map[string]any)
	obs, _ := get("observer").(map[string]any)
	host, _ := get("host").(map[string]any)
	raw := get("event.original")
	if raw == nil {
		raw = get("message")
	}
	return map[string]any{
		"schema_version": "1.0",
		"probe_id":       probeID,
		"alert_id":       h.ID,
		"timestamp":      ts,
		"source_type":    fmt.Sprintf("%v", ev["dataset"]),
		"event": map[string]any{
			"kind": ev["kind"], "category": ev["category"], "type": ev["type"],
			"severity": ev["severity"], "module": ev["module"], "dataset": ev["dataset"],
		},
		"rule":        get("rule"),
		"source":      get("source"),
		"destination": get("destination"),
		"network": map[string]any{
			"transport": netw["transport"], "protocol": netw["protocol"],
			"community_id": netw["community_id"],
		},
		"observer": map[string]any{"name": obs["name"], "hostname": host["name"]},
		"raw":      raw,
	}
}

func loadXdrPushConfig() xdrPushConfig {
	var c xdrPushConfig
	data, err := os.ReadFile(filepath.Join(confDir, "probe.yaml"))
	if err == nil {
		_ = yaml.Unmarshal(data, &c)
	}
	if c.XDR.PushIntervalS <= 0 {
		c.XDR.PushIntervalS = 2
	}
	if c.XDR.RetryMax <= 0 {
		c.XDR.RetryMax = 5
	}
	if len(c.XDR.EventTypes) == 0 {
		c.XDR.EventTypes = []string{"suricata.alert"}
	}
	return c
}

func loadXdrCursor() (xdrCursor, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "xdr-push-cursor.json"))
	if err != nil {
		return xdrCursor{}, err
	}
	var c xdrCursor
	err = json.Unmarshal(data, &c)
	return c, err
}

func saveXdrCursor(c xdrCursor) error {
	data, _ := json.Marshal(c)
	return os.WriteFile(filepath.Join(stateDir, "xdr-push-cursor.json"), data, 0o640)
}

func appendXdrDLQ(h xdrHit) error {
	line, _ := json.Marshal(h.Source)
	f, err := os.OpenFile(filepath.Join(stateDir, "xdr-push-dlq.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%s\t%s\n", h.ID, line))
	return err
}

// startXdrPush 线索上报调度（后台 goroutine，异常自动重试）
func startXdrPush() {
	go func() {
		time.Sleep(5 * time.Second)
		cfg := loadXdrPushConfig()
		if cfg.XDR.Webhook.URL == "" {
			log.Printf("warn: xdr.webhook.url 未配置，线索上报暂停（配置后自动恢复）")
		}
		poller := newXdrPoller()
		client := &xdrWebhookClient{cfg: cfg, client: &http.Client{Timeout: time.Duration(cfg.XDR.TimeoutS) * time.Second}}
		cursor, err := loadXdrCursor()
		if err != nil || cursor.TS == 0 {
			cursor = xdrCursor{TS: time.Now().Add(-time.Minute).UnixMilli(), ShardDoc: 0}
		}
		for {
			cfg = loadXdrPushConfig() // 每次读取，支持配置热更新
			if cfg.XDR.Webhook.URL == "" {
				time.Sleep(30 * time.Second)
				continue
			}
			hits, next, err := poller.Fetch(cursor)
			if err != nil {
				log.Printf("warn: 拉取线索失败: %v", err)
			} else {
				for _, h := range hits {
					if err := client.Push(h); err != nil {
						log.Printf("warn: 线索推送失败 %s: %v（写入死信）", h.ID, err)
						_ = appendXdrDLQ(h)
					}
				}
				if next != nil {
					cursor = *next
					_ = saveXdrCursor(cursor)
				}
			}
			time.Sleep(time.Duration(cfg.XDR.PushIntervalS) * time.Second)
		}
	}()
}
