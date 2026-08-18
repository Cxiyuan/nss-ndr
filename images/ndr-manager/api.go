package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type apiConfigSection struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Updated  string `json:"updated_at,omitempty"`
	Describe string `json:"describe"`
}

var sectionMeta = map[string]string{
	cfgProbe:         "探针基础：id / 镜像口 interface / HOME_NET / BPF / 磁盘阈值",
	cfgSuricata:      "Suricata：线程数 / pcap 全包留存与容量 / eve 留存",
	cfgZeek:          "Zeek：worker 数 / 缓冲 / 轮转间隔 / 历史与提取留存",
	cfgElasticsearch: "Elasticsearch：堆内存 / ILM 元数据与告警留存天数",
	cfgXdr:           "告警推送：Webhook URL / HMAC / 重试 / 推送事件白名单",
	cfgStrelka:       "Strelka：文件分析开关 / 扫描 worker 数 / 已扫描与日志留存",
}

func registerAPI(mux *http.ServeMux) {
	// 公开端点
	mux.HandleFunc("POST /api/login", apiLogin)
	mux.HandleFunc("GET /api/health", apiHealth)

	// 受保护端点
	mux.HandleFunc("POST /api/logout", requireAuth(apiLogout))
	mux.HandleFunc("POST /api/password", requireAuth(apiChangePassword))
	// XDR 分析任务下发（Bearer 令牌认证，见 apiXDRTask）
	mux.HandleFunc("POST /api/xdr/task", apiXDRTask)
	// XDR 分析任务（Agent 模式）：本地小模型 + MCP 工具自主分析
	mux.HandleFunc("POST /api/xdr/agent/task", apiXDRAgentTask)
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

	// ET Open 内置规则集（事件检测）
	mux.HandleFunc("GET /api/etopen/tree", requireAuth(apiETOpenTree))
	mux.HandleFunc("GET /api/etopen/rules", requireAuth(apiETOpenRules))
	mux.HandleFunc("POST /api/etopen/category/{cat}/enable", requireAuth(apiETOpenCategory(true)))
	mux.HandleFunc("POST /api/etopen/category/{cat}/disable", requireAuth(apiETOpenCategory(false)))
	mux.HandleFunc("POST /api/etopen/rule/{id}/enable", requireAuth(apiETOpenRule(true)))
	mux.HandleFunc("POST /api/etopen/rule/{id}/disable", requireAuth(apiETOpenRule(false)))

	// 运维监控可视化（仅本系统自身运维指标，不展示具体安全事件内容）
	mux.HandleFunc("GET /api/monitoring/traffic", requireAuth(apiMonitoringTraffic))
	mux.HandleFunc("GET /api/monitoring/workload", requireAuth(apiMonitoringWorkload))
	mux.HandleFunc("GET /api/monitoring/health", requireAuth(apiMonitoringHealth))
	mux.HandleFunc("GET /api/monitoring/alerts-today", requireAuth(apiMonitoringAlertsToday))

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
	writeJSON(w, http.StatusOK, store.ListCustom())
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
	if existing, err := store.Get(id); err == nil && (existing.Type == "etopen" || existing.Type == "builtin") {
		writeErr(w, http.StatusBadRequest, "内置规则不可编辑，仅可启停")
		return
	}
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
	if existing, err := store.Get(id); err == nil && (existing.Type == "etopen" || existing.Type == "builtin") {
		writeErr(w, http.StatusBadRequest, "内置规则不可删除")
		return
	}
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

// ---------- ET Open 内置规则集（事件检测） ----------

func apiETOpenTree(w http.ResponseWriter, _ *http.Request) {
	tree, err := etopenTree()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func apiETOpenRules(w http.ResponseWriter, r *http.Request) {
	cat := strings.TrimSpace(r.URL.Query().Get("category"))
	if cat == "" {
		writeErr(w, http.StatusBadRequest, "category 不能为空")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	offset := 0
	limit := 50
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	page, err := etopenListRules(cat, q, offset, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func apiETOpenCategory(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cat := r.PathValue("cat")
		n, err := etopenCategoryEnable(cat, enabled)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "category": cat, "enabled": enabled, "affected": n})
	}
}

func apiETOpenRule(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := etopenSetRule(id, enabled); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
