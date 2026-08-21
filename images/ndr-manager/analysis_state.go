// NDR 分析任务状态持久化（4 步流水线的中间状态）
//
// 用途：
//  1. 审计追溯：每个 task_id 的完整推理路径（metrics → heuristic → llm → xdr → final）
//  2. 崩溃恢复：XDR 升级超时/Agent 进程挂时，重启后可看到这个 task 卡在哪一步
//  3. 对接 XDR：XDR 平台可查询 NDR 的分析状态（用于 XDR 端 UI 展示）
//
// 设计原则：
//  - 状态由 Agent 推过来（PUT 整个 state 对象），不是 ndr-manager 主动拉
//  - 失败的 Agent 写状态不影响主流程（4 步流水线继续）
//  - JSON 列存储（schema-free，便于 Agent 演进字段）
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// AnalysisState NDR 分析任务状态（Agent 推过来）
type AnalysisState struct {
	TaskID          string `json:"task_id"`
	Instruction     string `json:"instruction"`
	Target          string `json:"target"`            // JSON 字符串
	Stage           string `json:"stage"`             // 当前阶段（pre_aggregate/heuristic/llm/escalated/finalized）
	Metrics         string `json:"metrics"`           // JSON 字符串
	HeuristicVerdict string `json:"heuristic_verdict"` // JSON 字符串
	LLMVerdict      string `json:"llm_verdict"`       // JSON 字符串
	XDRVerdict      string `json:"xdr_verdict"`        // JSON 字符串
	FinalVerdict    string `json:"final_verdict"`      // JSON 字符串
	LLMUsed         bool   `json:"llm_used"`
	Escalated       bool   `json:"escalated"`
	ElapsedMs       int    `json:"elapsed_ms"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// initAnalysisStateTable 创建分析状态表
func initAnalysisStateTable() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS analysis_state (
			task_id            TEXT PRIMARY KEY,
			instruction        TEXT,
			target             TEXT,
			stage              TEXT,
			metrics            TEXT,
			heuristic_verdict  TEXT,
			llm_verdict        TEXT,
			xdr_verdict        TEXT,
			final_verdict      TEXT,
			llm_used           INTEGER DEFAULT 0,
			escalated          INTEGER DEFAULT 0,
			elapsed_ms         INTEGER DEFAULT 0,
			created_at         TEXT,
			updated_at         TEXT
		)`)
	if err != nil {
		log.Fatalf("创建 analysis_state 表失败: %v", err)
	}
	log.Printf("analysis_state 表就绪")
}

// SaveAnalysisState 由 Agent 调用（PUT 整个 state 对象）
func SaveAnalysisState(s *AnalysisState) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if s.CreatedAt == "" {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := db.Exec(`
		INSERT INTO analysis_state(
			task_id, instruction, target, stage,
			metrics, heuristic_verdict, llm_verdict, xdr_verdict, final_verdict,
			llm_used, escalated, elapsed_ms, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET
			instruction = excluded.instruction,
			target = excluded.target,
			stage = excluded.stage,
			metrics = excluded.metrics,
			heuristic_verdict = excluded.heuristic_verdict,
			llm_verdict = excluded.llm_verdict,
			xdr_verdict = excluded.xdr_verdict,
			final_verdict = excluded.final_verdict,
			llm_used = excluded.llm_used,
			escalated = excluded.escalated,
			elapsed_ms = excluded.elapsed_ms,
			updated_at = excluded.updated_at`,
		s.TaskID, s.Instruction, s.Target, s.Stage,
		s.Metrics, s.HeuristicVerdict, s.LLMVerdict, s.XDRVerdict, s.FinalVerdict,
		boolToInt(s.LLMUsed), boolToInt(s.Escalated), s.ElapsedMs,
		s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("保存 analysis_state 失败: %w", err)
	}
	audit("analysis.state.save", s.TaskID, fmt.Sprintf("stage=%s llm=%v escalated=%v", s.Stage, s.LLMUsed, s.Escalated))
	return nil
}

// GetAnalysisState 查询（前端 / XDR 用于查看推理路径）
func GetAnalysisState(taskID string) (*AnalysisState, error) {
	var s AnalysisState
	var llmUsed, escalated int
	err := db.QueryRow(`
		SELECT task_id, instruction, target, stage,
		       metrics, heuristic_verdict, llm_verdict, xdr_verdict, final_verdict,
		       llm_used, escalated, elapsed_ms, created_at, updated_at
		FROM analysis_state WHERE task_id = ?`, taskID,
	).Scan(
		&s.TaskID, &s.Instruction, &s.Target, &s.Stage,
		&s.Metrics, &s.HeuristicVerdict, &s.LLMVerdict, &s.XDRVerdict, &s.FinalVerdict,
		&llmUsed, &escalated, &s.ElapsedMs, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.LLMUsed = llmUsed != 0
	s.Escalated = escalated != 0
	return &s, nil
}

// ListAnalysisStates 列出最近 N 条（前端仪表盘用）
func ListAnalysisStates(limit int) ([]AnalysisState, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.Query(`
		SELECT task_id, instruction, target, stage,
		       metrics, heuristic_verdict, llm_verdict, xdr_verdict, final_verdict,
		       llm_used, escalated, elapsed_ms, created_at, updated_at
		FROM analysis_state ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AnalysisState{}
	for rows.Next() {
		var s AnalysisState
		var llmUsed, escalated int
		if err := rows.Scan(
			&s.TaskID, &s.Instruction, &s.Target, &s.Stage,
			&s.Metrics, &s.HeuristicVerdict, &s.LLMVerdict, &s.XDRVerdict, &s.FinalVerdict,
			&llmUsed, &escalated, &s.ElapsedMs, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			continue
		}
		s.LLMUsed = llmUsed != 0
		s.Escalated = escalated != 0
		out = append(out, s)
	}
	return out, nil
}

// boolToInt 辅助函数
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// unmarshalJSONField 辅助：从 JSON 字符串字段解析（前端友好）
func unmarshalJSONField(raw string) any {
	if raw == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}