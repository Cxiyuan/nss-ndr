package main

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// setupSigmaTestDB 初始化内存 SQLite（sigma_rules/configs/audit）
func setupSigmaTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
CREATE TABLE sigma_rules (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL,
  category TEXT DEFAULT '', product TEXT DEFAULT '', service TEXT DEFAULT '',
  level TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'disabled',
  schedule TEXT NOT NULL DEFAULT '5m', last_run_at TEXT DEFAULT '',
  builtin INTEGER NOT NULL DEFAULT 0,
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
);`); err != nil {
		t.Fatal(err)
	}
}

func TestBuiltinSigmaImportAndConvert(t *testing.T) {
	setupSigmaTestDB(t)
	dir := "builtin-sigma"

	// 1) 全部规则文件可解析、包含 correlation 段
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("builtin-sigma 目录无规则文件: %v", err)
	}
	if len(files) != 13 {
		t.Fatalf("内置 Sigma 规则数量应为 13，实际 %d", len(files))
	}
	contents := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		sy, err := parseSigma(content)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", f, err)
		}
		if sy.Correlation == nil {
			t.Fatalf("%s 缺少 correlation 段", f)
		}
		if sy.Correlation.Clue == nil || sy.Correlation.Clue.Logsource.Product != "suricata" {
			t.Fatalf("%s clue 阶段应为 suricata", f)
		}
		contents[sy.ID] = content
	}

	// 2) 导入产品规则库：全部 builtin，stable 默认启用
	if err := importBuiltinSigma(dir); err != nil {
		t.Fatalf("importBuiltinSigma: %v", err)
	}
	rules := listSigmaRules()
	if len(rules) != 13 {
		t.Fatalf("导入后规则数应为 13，实际 %d", len(rules))
	}
	enabled := 0
	for _, r := range rules {
		if !r.Builtin {
			t.Fatalf("规则 %s 应为内置", r.ID)
		}
		if r.Status == "enabled" {
			enabled++
		}
	}
	if enabled != 13 {
		t.Fatalf("stable 内置规则应全部默认启用，实际 %d/13", enabled)
	}

	// 3) 阶段 EQL 转换验证（需要 sigma CLI；本地/CI 无则跳过）
	if _, err := exec.LookPath("sigma"); err != nil {
		t.Log("sigma CLI 不可用，跳过 EQL 转换验证")
		return
	}
	sigmaPipeline = filepath.Join(dir, "..", "sigma_so_pipeline.yaml")
	for id, content := range contents {
		sy, _ := parseSigma(content)
		if _, err := buildStageQuery(*sy.Correlation.Clue, "clue", id); err != nil {
			t.Fatalf("规则 %s clue 转换失败: %v", id, err)
		}
		if sy.Correlation.Confirm != nil {
			q, err := buildStageQuery(*sy.Correlation.Confirm, "confirm", id)
			if err != nil {
				t.Fatalf("规则 %s confirm 转换失败: %v", id, err)
			}
			// 确认阶段必须落到 zeek 数据集
			if len(q.Indexes) != 1 || q.Indexes[0] != "logs-zeek-so" {
				t.Fatalf("规则 %s confirm 索引异常: %v", id, q.Indexes)
			}
			if q.Filter == nil {
				t.Fatalf("规则 %s confirm 缺少 event.dataset 过滤", id)
			}
		}
	}
}
