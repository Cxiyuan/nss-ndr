// NDR 跨任务记忆：IP 信誉缓存
//
// 目的：避免对同一 IP 重复跑完整 4 步流水线。
// - 第一次分析：完整跑（heuristic + LLM + 可选 XDR），写缓存
// - 后续 24h 内再分析同一 IP：缓存命中 → 直接返回历史 verdict，跳过 MCP/LLM
// - 24h 后或缓存判定非高置信 → 重新完整分析
//
// 这是"用 SQL 实现跨任务记忆"的最简形态；
// 未来如需"自动注入到 LLM prompt 上下文"可升级到 LangGraph MemoryStore。
package main

import (
	"log"
)

// IPReputation 单条 IP 信誉记录
type IPReputation struct {
	IP             string  `json:"ip"`
	LastVerdict    string  `json:"last_verdict"`
	LastConfidence float64 `json:"last_confidence"`
	LastAnalyzedAt string  `json:"last_analyzed_at"`
	AnalysisCount  int     `json:"analysis_count"`
	ExpiresAt      string  `json:"expires_at"`
}

func initIPReputationTable() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_reputation (
			ip                TEXT PRIMARY KEY,
			last_verdict      TEXT,
			last_confidence   REAL,
			last_analyzed_at  TEXT,
			analysis_count    INTEGER DEFAULT 0,
			expires_at        TEXT
		)`)
	if err != nil {
		log.Fatalf("创建 ip_reputation 表失败: %v", err)
	}
	log.Printf("ip_reputation 表就绪")
}

// GetIPReputation 读取（不存在时返回 error）
func GetIPReputation(ip string) (*IPReputation, error) {
	var r IPReputation
	err := db.QueryRow(`
		SELECT ip, last_verdict, last_confidence, last_analyzed_at, analysis_count, expires_at
		FROM ip_reputation WHERE ip = ?`, ip,
	).Scan(&r.IP, &r.LastVerdict, &r.LastConfidence, &r.LastAnalyzedAt, &r.AnalysisCount, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UpsertIPReputation 写入或累加（analysis_count 累加）
func UpsertIPReputation(r *IPReputation) error {
	_, err := db.Exec(`
		INSERT INTO ip_reputation(ip, last_verdict, last_confidence, last_analyzed_at, analysis_count, expires_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_verdict = excluded.last_verdict,
			last_confidence = excluded.last_confidence,
			last_analyzed_at = excluded.last_analyzed_at,
			analysis_count = ip_reputation.analysis_count + 1,
			expires_at = excluded.expires_at`,
		r.IP, r.LastVerdict, r.LastConfidence, r.LastAnalyzedAt, r.AnalysisCount, r.ExpiresAt,
	)
	return err
}