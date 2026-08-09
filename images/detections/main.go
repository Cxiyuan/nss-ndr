package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ProbeConfig struct {
	Probe struct {
		ID string `yaml:"id"`
	} `yaml:"probe"`
	Detections struct {
		DefaultRuleset string `yaml:"default_ruleset"`
	} `yaml:"detections"`
}

const (
	confDir    = "/opt/so/conf"
	stateFile  = "/opt/so/state/detections.json"
	rulesDir   = "/opt/so/rules/suricata"
	rulesFile  = rulesDir + "/all-rulesets.rules"
	builtinDir = "/opt/so/builtin-rules"
)

var (
	store *Store
	cfg   ProbeConfig
)

func loadConfig() {
	data, err := os.ReadFile(filepath.Join(confDir, "probe.yaml"))
	if err != nil {
		log.Printf("warn: 读取 probe.yaml 失败: %v（使用默认配置）", err)
		return
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("warn: probe.yaml 解析失败: %v", err)
	}
}

func main() {
	loadConfig()

	store = NewStore(stateFile)
	if err := store.Load(); err != nil {
		log.Printf("warn: 状态加载失败: %v", err)
	}
	if err := store.ImportBuiltins(builtinDir); err != nil {
		log.Printf("warn: 内置规则导入失败: %v", err)
	}
	store.Apply()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleUI)
	mux.HandleFunc("GET /api/health", handleHealth)
	mux.HandleFunc("GET /api/rules", handleListRules)
	mux.HandleFunc("POST /api/rules", handleCreateRule)
	mux.HandleFunc("PUT /api/rules/{id}", handleUpdateRule)
	mux.HandleFunc("DELETE /api/rules/{id}", handleDeleteRule)
	mux.HandleFunc("POST /api/rules/{id}/enable", handleSetRuleEnabled(true))
	mux.HandleFunc("POST /api/rules/{id}/disable", handleSetRuleEnabled(false))
	mux.HandleFunc("POST /api/reload", handleReload)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("detections listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
