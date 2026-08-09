package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "probe_id": cfg.Probe.ID})
}

func handleListRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": store.List()})
}

func handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Rule     string `json:"rule"`
		Threshold string `json:"threshold"`
		Enabled  bool   `json:"enabled"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.Rule) == "" {
		writeErr(w, http.StatusBadRequest, "name 与 rule 不能为空")
		return
	}
	rule := Rule{
		ID:       newID("rule"),
		Name:     body.Name,
		Rule:     body.Rule,
		Threshold: body.Threshold,
		Type:     "custom",
		Enabled:  body.Enabled,
		Category: body.Category,
	}
	rule.CreatedAt = time.Now().UTC()
	store.Upsert(rule)
	if err := store.Apply(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, ok := store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "规则不存在")
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Rule     *string `json:"rule"`
		Threshold *string `json:"threshold"`
		Enabled  *bool   `json:"enabled"`
		Category *string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if body.Name != nil {
		rule.Name = *body.Name
	}
	if body.Rule != nil {
		rule.Rule = *body.Rule
	}
	if body.Threshold != nil {
		rule.Threshold = *body.Threshold
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	if body.Category != nil {
		rule.Category = *body.Category
	}
	store.Upsert(rule)
	if err := store.Apply(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !store.Delete(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "规则不存在")
		return
	}
	if err := store.Apply(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func handleSetRuleEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !store.SetEnabled(r.PathValue("id"), enabled) {
			writeErr(w, http.StatusNotFound, "规则不存在")
			return
		}
		if err := store.Apply(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

func handleReload(w http.ResponseWriter, _ *http.Request) {
	if err := store.Apply(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func newID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), rand.Int63())
}
