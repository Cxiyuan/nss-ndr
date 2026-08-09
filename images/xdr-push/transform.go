package main

import (
	"fmt"
	"time"
)

// buildPayload 将 ES 文档转换为 Webhook 告警报文（docs/架构设计 §5.8）
func buildPayload(h Hit, probeID string) map[string]any {
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

	return map[string]any{
		"schema_version": "1.0",
		"probe_id":       probeID,
		"alert_id":       h.ID,
		"timestamp":      ts,
		"source_type":    fmt.Sprintf("%v", ev["dataset"]),
		"event": map[string]any{
			"kind":           ev["kind"],
			"category":       ev["category"],
			"type":           ev["type"],
			"severity":       ev["severity"],
			"severity_label": ev["severity_label"],
			"module":         ev["module"],
			"dataset":        ev["dataset"],
			"action":         ev["action"],
		},
		"rule":        get("rule"),
		"source":      get("source"),
		"destination": get("destination"),
		"network": map[string]any{
			"transport":    netw["transport"],
			"protocol":     netw["protocol"],
			"community_id": netw["community_id"],
			"bytes":        netw["bytes"],
			"packets":      netw["packets"],
		},
		"observer": map[string]any{
			"name":     obs["name"],
			"hostname": host["name"],
		},
		"raw": nil,
	}
}
