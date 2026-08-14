package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func openDB() error {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	var err error
	db, err = sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	schema := `
CREATE TABLE IF NOT EXISTS configs (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS config_versions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  action     TEXT NOT NULL,
  comment    TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  action     TEXT NOT NULL,
  target     TEXT NOT NULL,
  detail     TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS rules (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  rule       TEXT NOT NULL,
  threshold  TEXT DEFAULT '',
  type       TEXT NOT NULL DEFAULT 'custom',
  enabled    INTEGER NOT NULL DEFAULT 0,
  category   TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sigma_rules (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  category    TEXT DEFAULT '',
  product     TEXT DEFAULT '',
  service     TEXT DEFAULT '',
  level       TEXT DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'disabled',
  schedule    TEXT NOT NULL DEFAULT '5m',
  last_run_at TEXT DEFAULT '',
  builtin     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS users (
  username      TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// 存量库迁移：补齐 builtin 列（首次出现报 duplicate column 忽略）
	_, _ = db.Exec("ALTER TABLE sigma_rules ADD COLUMN builtin INTEGER NOT NULL DEFAULT 0")
	return nil
}

func closeDB() {
	if db != nil {
		_ = db.Close()
	}
}

func audit(action, target, detail string) {
	_, err := db.Exec("INSERT INTO audit(action, target, detail) VALUES(?,?,?)", action, target, detail)
	if err != nil {
		log.Printf("warn: 审计写入失败: %v", err)
	}
}

func touchStateDir() error {
	return os.MkdirAll(filepath.Dir(dbPath), 0o750)
}
