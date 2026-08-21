// IP 信誉 API（Agent 读写）
//
// 端点：
//   GET  /api/agent/ip_reputation/{ip}  Agent 查
//   PUT  /api/agent/ip_reputation/{ip}  Agent 写（完整分析后）
//
// 鉴权：requireAgentAuth（与 /api/agent/analysis_state 共享 AGENT_TOKEN）
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// apiGetIPReputation Agent 查 IP 信誉（缓存未命中时返回 200 + analyzed=false）
func apiGetIPReputation(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "ip 不能为空")
		return
	}
	rep, err := GetIPReputation(ip)
	if err != nil {
		// 缓存未命中：返回 analyzed=false（不算错误）
		writeJSON(w, http.StatusOK, map[string]any{
			"ip":       ip,
			"analyzed": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":               rep.IP,
		"analyzed":         true,
		"last_verdict":     rep.LastVerdict,
		"last_confidence":  rep.LastConfidence,
		"last_analyzed_at": rep.LastAnalyzedAt,
		"analysis_count":   rep.AnalysisCount,
		"expires_at":       rep.ExpiresAt,
	})
}

// apiPutIPReputation Agent 写入 IP 信誉（完整分析后）
func apiPutIPReputation(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "ip 不能为空")
		return
	}
	var body struct {
		LastVerdict    string  `json:"last_verdict"`
		LastConfidence float64 `json:"last_confidence"`
		ExpiresAt      string  `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	// 默认 24h 后过期
	if body.ExpiresAt == "" {
		body.ExpiresAt = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rep := &IPReputation{
		IP:             ip,
		LastVerdict:    body.LastVerdict,
		LastConfidence: body.LastConfidence,
		LastAnalyzedAt: now,
		AnalysisCount:  1, // SQL ON CONFLICT 累加
		ExpiresAt:      body.ExpiresAt,
	}
	if err := UpsertIPReputation(rep); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit("ip_reputation.write", ip, fmt.Sprintf("verdict=%s confidence=%.2f", body.LastVerdict, body.LastConfidence))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}