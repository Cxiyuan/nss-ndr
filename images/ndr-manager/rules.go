// 规则管理（合并原 detections 服务）：SQLite 存储 + 渲染 all-rulesets.rules
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Rule      string `json:"rule"`
	Threshold string `json:"threshold,omitempty"`
	Type      string `json:"type"` // custom | builtin
	Enabled   bool   `json:"enabled"`
	Category  string `json:"category,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type RuleStore struct{}

var store = RuleStore{}

func (s RuleStore) List() []Rule {
	rows, err := db.Query("SELECT id,name,rule,threshold,type,enabled,category,created_at,updated_at FROM rules")
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Threshold, &r.Type, &enabled, &r.Category, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (s RuleStore) Get(id string) (Rule, error) {
	var r Rule
	var enabled int
	err := db.QueryRow("SELECT id,name,rule,threshold,type,enabled,category,created_at,updated_at FROM rules WHERE id=?", id).
		Scan(&r.ID, &r.Name, &r.Rule, &r.Threshold, &r.Type, &enabled, &r.Category, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	r.Enabled = enabled == 1
	return r, nil
}

func (s RuleStore) Upsert(r Rule) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.ID == "" {
		r.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	_, err := db.Exec(`INSERT INTO rules(id,name,rule,threshold,type,enabled,category,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, rule=excluded.rule, threshold=excluded.threshold,
		type=excluded.type, enabled=excluded.enabled, category=excluded.category, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Rule, r.Threshold, r.Type, enabled, r.Category, r.CreatedAt, r.UpdatedAt)
	if err == nil {
		audit("rule.update", r.ID, r.Name)
	}
	return err
}

func (s RuleStore) Delete(id string) error {
	_, err := db.Exec("DELETE FROM rules WHERE id=?", id)
	if err == nil {
		audit("rule.delete", id, "")
	}
	return err
}

func (s RuleStore) SetEnabled(id string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := db.Exec("UPDATE rules SET enabled=?, updated_at=? WHERE id=?", v, time.Now().UTC().Format(time.RFC3339), id)
	if err == nil {
		audit("rule.enabled", id, fmt.Sprint(enabled))
	}
	return err
}

func (s RuleStore) EnabledRules() []Rule {
	out := []Rule{}
	for _, r := range s.List() {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func (s RuleStore) LoadRules() error {
	// SQLite 持久化，无需迁移；此处仅为兼容接口
	return nil
}

func (s RuleStore) ImportBuiltins(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		cat := strings.TrimSuffix(e.Name(), ".rules")
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 内置规则以固定 id 导入（幂等）
			_, err := db.Exec(`INSERT OR IGNORE INTO rules(id,name,rule,type,enabled,category,created_at,updated_at)
				VALUES(?,?,?,?,0,?,datetime('now'),datetime('now'))`,
				"builtin-"+fmt.Sprint(hashString(line)), truncate(line, 60), line, cat)
			if err != nil {
				continue
			}
		}
	}
	return nil
}

func hashString(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// renderRulesFile 把启用规则写入 /opt/so/rules/suricata/all-rulesets.rules
func renderRulesFile() error {
	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		return err
	}
	content := renderRulesContent()
	if err := os.WriteFile(rulesFile, []byte(content), 0o640); err != nil {
		return err
	}
	return nil
}
