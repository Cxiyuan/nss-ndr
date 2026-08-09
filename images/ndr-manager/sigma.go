// Sigma 规则管理：SQLite 存储 + 内置规则导入（对齐 SO 3.1.0 的 detections 模型）
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SigmaRule struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Category  string `json:"category"`
	Product   string `json:"product"`
	Service   string `json:"service"`
	Level     string `json:"level"`
	Status    string `json:"status"` // enabled | disabled
	Schedule  string `json:"schedule"` // 执行间隔，如 5m
	LastRunAt string `json:"last_run_at,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// sigmaYAML 是 Sigma 规则文件的 YAML 结构（解析所需子集）
type sigmaYAML struct {
	Title     string `yaml:"title"`
	ID        string `yaml:"id"`
	Status    string `yaml:"status"`
	Level     string `yaml:"level"`
	Logsource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

func parseSigma(content string) (*sigmaYAML, error) {
	var sy sigmaYAML
	if err := yaml.Unmarshal([]byte(content), &sy); err != nil {
		return nil, fmt.Errorf("Sigma YAML 解析失败: %w", err)
	}
	if sy.Title == "" {
		return nil, fmt.Errorf("Sigma 规则缺少 title")
	}
	if sy.Detection == nil || len(sy.Detection) == 0 {
		return nil, fmt.Errorf("Sigma 规则缺少 detection 段")
	}
	return &sy, nil
}

func (s SigmaRule) load(id string) error {
	err := db.QueryRow(`SELECT id,title,content,category,product,service,level,status,schedule,last_run_at,created_at,updated_at
		FROM sigma_rules WHERE id=?`, id).
		Scan(&s.ID, &s.Title, &s.Content, &s.Category, &s.Product, &s.Service, &s.Level, &s.Status, &s.Schedule, &s.LastRunAt, &s.CreatedAt, &s.UpdatedAt)
	return err
}

func listSigmaRules() []SigmaRule {
	rows, err := db.Query(`SELECT id,title,content,category,product,service,level,status,schedule,last_run_at,created_at,updated_at FROM sigma_rules`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []SigmaRule{}
	for rows.Next() {
		var r SigmaRule
		if err := rows.Scan(&r.ID, &r.Title, &r.Content, &r.Category, &r.Product, &r.Service, &r.Level, &r.Status, &r.Schedule, &r.LastRunAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func upsertSigmaRule(r SigmaRule) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.ID == "" {
		r.ID = sigmaPublicID(r.Content)
	}
	if r.Status == "" {
		r.Status = "disabled"
	}
	if r.Schedule == "" {
		r.Schedule = "5m"
	}
	// 解析校验 + 提取元数据
	sy, err := parseSigma(r.Content)
	if err != nil {
		return err
	}
	if r.Title == "" {
		r.Title = sy.Title
	}
	if sy.ID != "" {
		r.ID = sy.ID
	}
	r.Category = sy.Logsource.Category
	r.Product = sy.Logsource.Product
	r.Service = sy.Logsource.Service
	r.Level = sy.Level
	_, err = db.Exec(`INSERT INTO sigma_rules(id,title,content,category,product,service,level,status,schedule,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET title=excluded.title, content=excluded.content, category=excluded.category,
		product=excluded.product, service=excluded.service, level=excluded.level, status=excluded.status,
		schedule=excluded.schedule, updated_at=excluded.updated_at`,
		r.ID, r.Title, r.Content, r.Category, r.Product, r.Service, r.Level, r.Status, r.Schedule, now, now)
	if err == nil {
		audit("sigma.upsert", r.ID, r.Title)
	}
	return err
}

func deleteSigmaRule(id string) error {
	_, err := db.Exec("DELETE FROM sigma_rules WHERE id=?", id)
	if err == nil {
		audit("sigma.delete", id, "")
	}
	return err
}

func setSigmaRuleStatus(id, status string) error {
	_, err := db.Exec("UPDATE sigma_rules SET status=?, updated_at=? WHERE id=?", status, time.Now().UTC().Format(time.RFC3339), id)
	if err == nil {
		audit("sigma.status", id, status)
	}
	return err
}

func sigmaPublicID(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sigma-" + hex.EncodeToString(sum[:8])
}

// importBuiltinSigma 导入镜像内置规则（幂等，按 id 不覆盖用户修改）
func importBuiltinSigma(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sy, err := parseSigma(string(data))
		if err != nil {
			continue
		}
		id := sy.ID
		if id == "" {
			id = sigmaPublicID(string(data))
		}
		_, err = db.Exec(`INSERT OR IGNORE INTO sigma_rules(id,title,content,category,product,service,level,status,schedule,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?, 'disabled','5m',datetime('now'),datetime('now'))`,
			id, sy.Title, string(data), sy.Logsource.Category, sy.Logsource.Product, sy.Logsource.Service, sy.Level)
		if err != nil {
			continue
		}
	}
	return nil
}

func enabledSigmaRules() []SigmaRule {
	out := []SigmaRule{}
	for _, r := range listSigmaRules() {
		if r.Status == "enabled" {
			out = append(out, r)
		}
	}
	return out
}
