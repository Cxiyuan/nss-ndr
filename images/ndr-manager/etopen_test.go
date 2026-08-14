package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestETOpenImportTreeAndRender(t *testing.T) {
	tmp := t.TempDir()
	// 复制内置规则包与元数据到临时目录
	for _, name := range []string{"etopen-rules.tar.gz", "categories.json"} {
		data, err := os.ReadFile(filepath.Join("etopen", name))
		if err != nil {
			t.Fatalf("读取 %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o640); err != nil {
			t.Fatalf("写入 %s: %v", name, err)
		}
	}
	etopenDir = tmp
	etopenBundle = filepath.Join(tmp, "etopen-rules.tar.gz")
	etopenMetaFile = filepath.Join(tmp, "categories.json")
	etopenRulesDir = filepath.Join(tmp, "rules")

	// 内存 SQLite + 最小 schema
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
CREATE TABLE rules (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, rule TEXT NOT NULL,
  threshold TEXT DEFAULT '', type TEXT NOT NULL DEFAULT 'custom',
  enabled INTEGER NOT NULL DEFAULT 0, category TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE configs (
  key TEXT PRIMARY KEY, value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
  target TEXT NOT NULL, detail TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE sigma_rules (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL,
  category TEXT DEFAULT '', product TEXT DEFAULT '', service TEXT DEFAULT '',
  level TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'disabled',
  schedule TEXT NOT NULL DEFAULT '5m', last_run_at TEXT DEFAULT '',
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);`); err != nil {
		t.Fatal(err)
	}

	if err := importETOpen(); err != nil {
		t.Fatalf("importETOpen: %v", err)
	}

	// 版本化：再次导入应跳过且不重复
	if err := importETOpen(); err != nil {
		t.Fatalf("importETOpen(2): %v", err)
	}
	var total int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE type='etopen'").Scan(&total)
	if total < 30000 {
		t.Fatalf("导入规则数异常: %d", total)
	}

	tree, err := etopenTree()
	if err != nil {
		t.Fatalf("etopenTree: %v", err)
	}
	// 分组数（exploit/web/lateral/malware/protocol）
	if len(tree) != 5 {
		t.Fatalf("分组数异常: %d", len(tree))
	}
	var exploitTotal int
	for _, g := range tree {
		for _, c := range g.Categories {
			if c.Key == "exploit" {
				exploitTotal = c.Total
			}
			if c.Key == "info" || c.Key == "chat" || c.Key == "games" || c.Key == "inappropriate" {
				t.Fatalf("被排除分类仍出现在树中: %s", c.Key)
			}
		}
	}
	if exploitTotal < 1500 {
		t.Fatalf("exploit 分类规则数异常: %d", exploitTotal)
	}

	// 分类启停
	if _, err := etopenCategoryEnable("exploit", true); err != nil {
		t.Fatalf("etopenCategoryEnable: %v", err)
	}
	var enabledCount int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE type='etopen' AND enabled=1").Scan(&enabledCount)
	if enabledCount != exploitTotal {
		t.Fatalf("分类启用后 enabled 数异常: %d != %d", enabledCount, exploitTotal)
	}

	// 渲染应包含启用规则
	content := renderRulesContent()
	if !strings.Contains(content, "ET EXPLOIT") {
		t.Fatalf("启用 exploit 分类后渲染内容应包含 ET EXPLOIT 规则")
	}

	// 分页查询
	page, err := etopenListRules("exploit", "", 0, 20)
	if err != nil {
		t.Fatalf("etopenListRules: %v", err)
	}
	if page.Total != exploitTotal || len(page.Rules) != 20 {
		t.Fatalf("分页结果异常: total=%d len=%d", page.Total, len(page.Rules))
	}

	// 自定义规则列表不应包含 etopen
	if rules := store.ListCustom(); len(rules) != 0 {
		t.Fatalf("ListCustom 应过滤 ET Open，实际 %d 条", len(rules))
	}

	// 内置 Sigma 规则库：导入为 builtin，仅可启停
	sigmaDir := filepath.Join(tmp, "builtin-sigma")
	if err := os.MkdirAll(sigmaDir, 0o750); err != nil {
		t.Fatal(err)
	}
	builtinSigma := `title: 测试内置事件告警
id: 11111111-2222-3333-4444-555555555555
status: test
level: medium
logsource:
  product: zeek
  category: dns
detection:
  selection:
    dns.question.name|endswith: ".xyz"
  condition: selection
`
	if err := os.WriteFile(filepath.Join(sigmaDir, "builtin-test.yml"), []byte(builtinSigma), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := importBuiltinSigma(sigmaDir); err != nil {
		t.Fatalf("importBuiltinSigma: %v", err)
	}
	sigmas := listSigmaRules()
	if len(sigmas) != 1 || !sigmas[0].Builtin {
		t.Fatalf("内置 Sigma 规则应导入且 builtin=true: %+v", sigmas)
	}
	if !builtinSigmaRule("11111111-2222-3333-4444-555555555555") {
		t.Fatalf("builtinSigmaRule 应识别内置规则")
	}
}
