// NSS-NDR Manager：统一配置管理后台（Web UI + API + 配置渲染/下发 + 规则管理）
package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
)

//go:embed web/dist
var webFS embed.FS

const (
	confDir   = "/opt/so/conf"           // ConfigMap 挂载（只读参考）
	rulesDir  = "/opt/so/rules/suricata" // 规则文件目录（hostPath，suricata 读取）
	rulesFile = rulesDir + "/all-rulesets.rules"
	stateDir  = "/opt/so/state"
	dbPath    = "/opt/so/state/manager.db"
)

func main() {
	if err := openDB(); err != nil {
		log.Fatalf("SQLite 初始化失败: %v", err)
	}
	defer closeDB()

	if err := ensureDefaults(); err != nil {
		log.Fatalf("默认配置初始化失败: %v", err)
	}
	if err := ensureAdmin(); err != nil {
		log.Fatalf("管理员账号初始化失败: %v", err)
	}
	if err := store.LoadRules(); err != nil {
		log.Printf("warn: 规则加载失败: %v", err)
	}
	if err := store.ImportBuiltins("/opt/so/builtin-rules"); err != nil {
		log.Printf("warn: 内置规则导入失败: %v", err)
	}
	if err := importETOpen(); err != nil {
		log.Printf("warn: ET Open 内置规则集导入失败: %v", err)
	}

	// 首次启动：若规则文件不存在则渲染初始规则集
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		if err := renderRulesFile(); err != nil {
			log.Printf("warn: 初始规则文件渲染失败: %v", err)
		}
	}

	mux := http.NewServeMux()
	registerAPI(mux)
	registerStatic(mux)

	// 后台任务（并入的 es-init / xdr-push / cleaner 功能）
	startESInit()
	startXdrPush()
	startCleaner()

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("ndr-manager listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func registerStatic(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "web/dist")
	if err != nil {
		log.Fatalf("前端资源加载失败: %v", err)
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			http.NotFound(w, r)
			return
		}
		// SPA 路由回退到 index.html
		if _, err := fs.Stat(sub, r.URL.Path[1:]); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	}))
}