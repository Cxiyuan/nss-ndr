// Sigma 规则管理：SQLite 存储 + 内置规则导入（对齐 SO 3.1.0 的 detections 模型）
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
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

// legacyBuiltinSigmaIDs 是旧版本镜像内置 Sigma 规则的固定 UUID
// （2026-08-14 起产品不再内置 Sigma 规则；启动时清理历史残留）
var legacyBuiltinSigmaIDs = []string{
	"01584916-9b8b-4295-834a-6a773626f974", // High Volume DNS Queries from Single Host
	"e343eba1-094f-4549-8428-203dc1c4f28d", // Suspicious DNS Query for Dynamic DNS Domain
	"7f040f96-d846-4dd0-9411-c46186fad64e", // Suspicious HTTP Request URI
	"904da9e2-11ce-4ade-8aab-6d7099395a31", // Connection Attempt to Uncommon Port
	"7cc5f183-3c9c-4e93-aa84-096166b5ce6e", // Suspicious TLS Connection (Known Bad Cipher)
}

// purgeLegacyBuiltinSigma 清理旧版本内置 Sigma 规则（升级后不再残留；仅删除已知内置 ID，不影响用户导入的规则）
func purgeLegacyBuiltinSigma() error {
	placeholders := make([]string, len(legacyBuiltinSigmaIDs))
	args := make([]any, 0, len(legacyBuiltinSigmaIDs))
	for i, id := range legacyBuiltinSigmaIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	res, err := db.Exec("DELETE FROM sigma_rules WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("已清理 %d 条旧版内置 Sigma 规则", n)
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
