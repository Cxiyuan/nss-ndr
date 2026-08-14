package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type apiConfigSection struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Updated  string `json:"updated_at,omitempty"`
	Describe string `json:"describe"`
}

var sectionMeta = map[string]string{
	cfgProbe:        "探针基础：id / 镜像口 interface / HOME_NET / BPF / 磁盘阈值",
	cfgSuricata:     "Suricata：线程数 / pcap 全包留存与容量 / eve 留存",
	cfgZeek:         "Zeek：worker 数 / 缓冲 / 轮转间隔 / 历史与提取留存",
	cfgElasticsearch: "Elasticsearch：堆内存 / ILM 元数据与告警留存天数",
	cfgXdr:          "告警推送：Webhook URL / HMAC / 重试 / 推送事件白名单",
	cfgStrelka:      "Strelka：文件分析开关 / 扫描 worker 数 / 已扫描与日志留存",
}

func registerAPI(mux *http.ServeMux) {
	// 公开端点
	mux.HandleFunc("POST /api/login", apiLogin)
	mux.HandleFunc("GET /api/health", apiHealth)

	// 受保护端点
	mux.HandleFunc("POST /api/logout", requireAuth(apiLogout))
	mux.HandleFunc("POST /api/password", requireAuth(apiChangePassword))
	// Kibana 看板代理（iframe 同源嵌入，自动维护 Kibana 会话）
	// 按具体方法注册，避免与 SPA 兜底路由 "GET /" 冲突（Go 1.22+ ServeMux 规则）
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"} {
		mux.Handle(m+" /kibana/", requireAuth(kibanaProxy.ServeHTTP))
	}
	mux.HandleFunc("GET /api/config", requireAuth(apiGetFullConfig))
	mux.HandleFunc("GET /api/config/schema", requireAuth(apiConfigSchema))
	mux.HandleFunc("PUT /api/config", requireAuth(apiSaveFormConfig))
	mux.HandleFunc("GET /api/configs", requireAuth(apiListSections))
	mux.HandleFunc("GET /api/configs/{key}", requireAuth(apiGetSection))
	mux.HandleFunc("PUT /api/configs/{key}", requireAuth(apiSaveSection))
	mux.HandleFunc("POST /api/apply", requireAuth(apiApply))
	mux.HandleFunc("GET /api/status", requireAuth(apiStatus))
	mux.HandleFunc("GET /api/history", requireAuth(apiHistory))
	mux.HandleFunc("GET /api/audit", requireAuth(apiAudit))

	mux.HandleFunc("GET /api/rules", requireAuth(apiListRules))
	mux.HandleFunc("POST /api/rules", requireAuth(apiCreateRule))
	mux.HandleFunc("PUT /api/rules/{id}", requireAuth(apiUpdateRule))
	mux.HandleFunc("DELETE /api/rules/{id}", requireAuth(apiDeleteRule))
	mux.HandleFunc("POST /api/rules/{id}/enable", requireAuth(apiSetRuleEnabled(true)))
	mux.HandleFunc("POST /api/rules/{id}/disable", requireAuth(apiSetRuleEnabled(false)))
	mux.HandleFunc("POST /api/rules/apply", requireAuth(apiApplyRules))
	mux.HandleFunc("GET /api/suricata/stats", requireAuth(apiSuricataStats))

	mux.HandleFunc("GET /api/sigma", requireAuth(apiListSigma))
	mux.HandleFunc("POST /api/sigma", requireAuth(apiCreateSigma))
	mux.HandleFunc("POST /api/sigma/import", requireAuth(apiImportSigma))
	mux.HandleFunc("GET /api/sigma/{id}", requireAuth(apiGetSigma))
	mux.HandleFunc("PUT /api/sigma/{id}", requireAuth(apiUpdateSigma))
	mux.HandleFunc("DELETE /api/sigma/{id}", requireAuth(apiDeleteSigma))
	mux.HandleFunc("POST /api/sigma/{id}/enable", requireAuth(apiSetSigmaStatus("enabled")))
	mux.HandleFunc("POST /api/sigma/{id}/disable", requireAuth(apiSetSigmaStatus("disabled")))
	mux.HandleFunc("POST /api/sigma/{id}/run", requireAuth(apiRunSigma))
	mux.HandleFunc("GET /api/sigma/{id}/preview", requireAuth(apiPreviewSigma))
	mux.HandleFunc("GET /api/sigma/{id}/evidence", requireAuth(apiEvidenceSigma))
}

func apiHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "nss-ndr-manager"})
}

func apiGetFullConfig(w http.ResponseWriter, _ *http.Request) {
	c, err := loadFull()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func apiListSections(w http.ResponseWriter, _ *http.Request) {
	out := []apiConfigSection{}
	for _, key := range []string{cfgProbe, cfgSuricata, cfgZeek, cfgElasticsearch, cfgXdr, cfgStrelka} {
		val, _ := getSection(key)
		out = append(out, apiConfigSection{Key: key, Value: val, Describe: sectionMeta[key]})
	}
	writeJSON(w, http.StatusOK, out)
}

func apiGetSection(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	val, err := getSection(key)
	if err != nil {
		writeErr(w, http.StatusNotFound, "配置分组不存在")
		return
	}
	writeJSON(w, http.StatusOK, apiConfigSection{Key: key, Value: val, Describe: sectionMeta[key]})
}

func apiSaveSection(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if _, ok := sectionMeta[key]; !ok {
		writeErr(w, http.StatusBadRequest, "未知配置分组")
		return
	}
	var body struct {
		Value   string `json:"value"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := saveSection(key, body.Value, body.Comment); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key})
}

func apiApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Comment string `json:"comment"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := applyConfig(body.Comment); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "配置已下发并重启组件"})
}

func apiStatus(w http.ResponseWriter, _ *http.Request) {
	c, err := loadFull()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"probe_id":     c.Probe.ID,
		"interface":    c.Probe.Interface,
		"applied_hash": configMapHash(),
		"time":         nowStr(),
	})
}

func apiSuricataStats(w http.ResponseWriter, _ *http.Request) {
	stats, err := suricataStats()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func apiHistory(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query("SELECT id,key,action,comment,created_at FROM config_versions ORDER BY id DESC LIMIT 100")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var key, action, comment, created string
		if err := rows.Scan(&id, &key, &action, &comment, &created); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "key": key, "action": action, "comment": comment, "created_at": created})
	}
	writeJSON(w, http.StatusOK, out)
}

func apiAudit(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query("SELECT id,action,target,detail,created_at FROM audit ORDER BY id DESC LIMIT 200")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var action, target, detail, created string
		if err := rows.Scan(&id, &action, &target, &detail, &created); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "action": action, "target": target, "detail": detail, "created_at": created})
	}
	writeJSON(w, http.StatusOK, out)
}

// 规则 handlers
func apiListRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, store.List())
}

func apiCreateRule(w http.ResponseWriter, r *http.Request) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Rule) == "" {
		writeErr(w, http.StatusBadRequest, "name 与 rule 不能为空")
		return
	}
	if rule.Type == "" {
		rule.Type = "custom"
	}
	if err := store.Upsert(rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func apiUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	rule.ID = id
	if err := store.Upsert(rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func apiDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := store.Delete(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func apiSetRuleEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := store.SetEnabled(id, enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

func apiApplyRules(w http.ResponseWriter, _ *http.Request) {
	if err := applyRules(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "规则已渲染，suricata 热加载触发"})
}

// Sigma handlers
func apiListSigma(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, listSigmaRules())
}

func apiGetSigma(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, rule := range listSigmaRules() {
		if rule.ID == id {
			writeJSON(w, http.StatusOK, rule)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "Sigma 规则不存在")
}

func apiCreateSigma(w http.ResponseWriter, r *http.Request) {
	var rule SigmaRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if strings.TrimSpace(rule.Content) == "" {
		writeErr(w, http.StatusBadRequest, "Sigma 规则内容不能为空")
		return
	}
	if err := upsertSigmaRule(rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func apiImportSigma(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := upsertSigmaRule(SigmaRule{Content: body.Content}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiUpdateSigma(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule SigmaRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	rule.ID = id
	if err := upsertSigmaRule(rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func apiDeleteSigma(w http.ResponseWriter, r *http.Request) {
	if err := deleteSigmaRule(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func apiSetSigmaStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := setSigmaRuleStatus(r.PathValue("id"), status); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

func apiRunSigma(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule SigmaRule
	for _, x := range listSigmaRules() {
		if x.ID == id {
			rule = x
			break
		}
	}
	if rule.ID == "" {
		writeErr(w, http.StatusNotFound, "Sigma 规则不存在")
		return
	}
	if err := executeSigmaRule(rule, 10*time.Minute); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "检测已执行"})
}

func apiPreviewSigma(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule SigmaRule
	for _, x := range listSigmaRules() {
		if x.ID == id {
			rule = x
			break
		}
	}
	if rule.ID == "" {
		writeErr(w, http.StatusNotFound, "Sigma 规则不存在")
		return
	}
	sy, err := parseSigma(rule.Content)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sy.Correlation != nil {
		out := map[string]any{
			"type":       "correlation",
			"group_by":   sy.Correlation.GroupBy,
			"required":   sy.Correlation.Required,
			"fallback":   sy.Correlation.Fallback,
			"confidence": sy.Correlation.Confidence,
			"timespan":   sy.Correlation.Timespan,
			"backend":    sy.Backend,
		}
		if sy.Correlation.Clue != nil {
			sq, err := buildStageQuery(*sy.Correlation.Clue, rule.Title, rule.ID)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "线索查询转换失败: "+err.Error())
				return
			}
			out["clue"] = sq
		}
		if sy.Correlation.Confirm != nil {
			sq, err := buildStageQuery(*sy.Correlation.Confirm, rule.Title, rule.ID)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "确认查询转换失败: "+err.Error())
				return
			}
			out["confirm"] = sq
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	sq, err := buildSigmaQuery(rule.Content)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sq)
}

// apiEvidenceSigma 证据预览（dry-run）：不写告警，返回关联命中组或普通规则命中文档
func apiEvidenceSigma(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	window := 10 * time.Minute
	if ws := r.URL.Query().Get("window"); ws != "" {
		if d := parseInterval(ws); d > 0 {
			window = d
		}
	}
	var rule SigmaRule
	for _, x := range listSigmaRules() {
		if x.ID == id {
			rule = x
			break
		}
	}
	if rule.ID == "" {
		writeErr(w, http.StatusNotFound, "Sigma 规则不存在")
		return
	}
	sy, err := parseSigma(rule.Content)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sy.Correlation != nil {
		if ts := parseInterval(sy.Correlation.Timespan); ts > 0 {
			window = ts
		}
		matches, err := executeCorrelationRule(rule, sy.Correlation, window, true)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"type":    "correlation",
			"window":  window.String(),
			"matches": matches,
			"count":   len(matches),
		})
		return
	}
	sq, err := buildSigmaQuery(rule.Content)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	hits, err := runSigmaQuery(sq, now.Add(-window), now, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type":   "simple",
		"window": window.String(),
		"hits":   summarizeHits(hits),
		"count":  len(hits),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
