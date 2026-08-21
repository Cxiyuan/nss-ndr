// NDR 分析状态 API 端点（Agent 写 / 前端+XDR 读）
//
// Agent 主动写：PUT /api/agent/analysis_state/{task_id}（agent auth）
// 前端/XDR 读：GET /api/analysis/{task_id}（user auth）
// 列表：    GET /api/analysis?limit=50（user auth）
package main

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// apiSaveAnalysisState Agent 回调：保存分析状态
func apiSaveAnalysisState(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("task_id")
	if taskID == "" {
		writeErr(w, http.StatusBadRequest, "task_id 不能为空")
		return
	}
	var s AnalysisState
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	// 强制覆盖（task_id 来自 URL）
	s.TaskID = taskID
	if s.Stage == "" {
		s.Stage = "finalized"
	}
	if err := SaveAnalysisState(&s); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": taskID})
}

// apiGetAnalysisState 读取单条分析状态（含完整推理路径）
func apiGetAnalysisState(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("task_id")
	if taskID == "" {
		writeErr(w, http.StatusBadRequest, "task_id 不能为空")
		return
	}
	s, err := GetAnalysisState(taskID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "分析任务不存在: "+taskID)
		return
	}
	// 解析 JSON 字段（前端友好：直接拿到 Python-style dict 而不是字符串）
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":           s.TaskID,
		"instruction":       s.Instruction,
		"target":            unmarshalJSONField(s.Target),
		"stage":             s.Stage,
		"metrics":           unmarshalJSONField(s.Metrics),
		"heuristic_verdict": unmarshalJSONField(s.HeuristicVerdict),
		"llm_verdict":       unmarshalJSONField(s.LLMVerdict),
		"xdr_verdict":       unmarshalJSONField(s.XDRVerdict),
		"final_verdict":     unmarshalJSONField(s.FinalVerdict),
		"llm_used":          s.LLMUsed,
		"escalated":         s.Escalated,
		"elapsed_ms":        s.ElapsedMs,
		"created_at":        s.CreatedAt,
		"updated_at":        s.UpdatedAt,
	})
}

// apiListAnalysisStates 列出最近 N 条分析任务
func apiListAnalysisStates(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := ListAnalysisStates(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []map[string]any{}
	for _, s := range rows {
		out = append(out, map[string]any{
			"task_id":      s.TaskID,
			"instruction":  s.Instruction,
			"stage":        s.Stage,
			"verdict":      extractVerdict(s.FinalVerdict),
			"confidence":   extractConfidence(s.FinalVerdict),
			"llm_used":     s.LLMUsed,
			"escalated":    s.Escalated,
			"elapsed_ms":   s.ElapsedMs,
			"updated_at":   s.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// extractVerdict 从 final_verdict JSON 提取 verdict 字段
func extractVerdict(raw string) string {
	if raw == "" {
		return ""
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return ""
	}
	if s, ok := v["verdict"].(string); ok {
		return s
	}
	return ""
}

// extractConfidence 从 final_verdict JSON 提取 confidence 字段
func extractConfidence(raw string) float64 {
	if raw == "" {
		return 0
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return 0
	}
	if f, ok := v["confidence"].(float64); ok {
		return f
	}
	return 0
}