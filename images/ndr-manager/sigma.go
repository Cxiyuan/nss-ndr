// Sigma 规则管理：SQLite 存储 + 内置规则导入（对齐 SO 3.1.0 的 detections 模型）
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
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
	Status    string `json:"status"`   // enabled | disabled
	Schedule  string `json:"schedule"` // 执行间隔，如 5m
	LastRunAt string `json:"last_run_at,omitempty"`
	Builtin   bool   `json:"builtin,omitempty"` // 内置产品规则库：仅可启停，不可编辑/删除
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// 以下为读取时由 enrichSigmaRule 填充的视图字段（不入库）
	Type        string           `json:"type,omitempty"` // simple | correlation
	Backend     string           `json:"backend,omitempty"`
	Correlation *correlationView `json:"correlation,omitempty"`
}

// sigmaYAML 是 Sigma 规则文件的 YAML 结构（解析所需子集）
type sigmaYAML struct {
	Title     string `yaml:"title"`
	ID        string `yaml:"id"`
	Status    string `yaml:"status"`
	Level     string `yaml:"level"`
	Backend   string `yaml:"backend"` // eql | esql | auto
	Logsource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection   map[string]any    `yaml:"detection"`
	Correlation *sigmaCorrelation `yaml:"correlation"`
}

// sigmaCorrelation 是 NSS-NDR 扩展的关联规则段（三层信号模型）：
//
//	clue    阶段1 线索（默认 suricata.alert 命中）
//	confirm 阶段2 确认（默认 zeek 元数据条件）
//
// 两侧事件按 group_by 字段（默认 network.community_id）在时间窗内关联。
type sigmaCorrelation struct {
	Clue       *sigmaStage `yaml:"clue"`
	Confirm    *sigmaStage `yaml:"confirm"`
	GroupBy    string      `yaml:"group_by"`
	Timespan   string      `yaml:"timespan"`
	Required   string      `yaml:"required"`   // both | clue | confirm
	Fallback   string      `yaml:"fallback"`   // none | clue_only | confirm_only
	Confidence string      `yaml:"confidence"` // low | medium | high
}

type sigmaStage struct {
	Logsource sigmaLogsource `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

type sigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// correlationView 是 API/UI 展示用的关联规则元数据
type correlationView struct {
	ClueProduct    string `json:"clue_product,omitempty"`
	ConfirmProduct string `json:"confirm_product,omitempty"`
	GroupBy        string `json:"group_by"`
	Timespan       string `json:"timespan,omitempty"`
	Required       string `json:"required"`
	Fallback       string `json:"fallback"`
	Confidence     string `json:"confidence"`
}

func parseSigma(content string) (*sigmaYAML, error) {
	var sy sigmaYAML
	if err := yaml.Unmarshal([]byte(content), &sy); err != nil {
		return nil, fmt.Errorf("Sigma YAML 解析失败: %w", err)
	}
	if sy.Title == "" {
		return nil, fmt.Errorf("Sigma 规则缺少 title")
	}
	if (sy.Detection == nil || len(sy.Detection) == 0) && sy.Correlation == nil {
		return nil, fmt.Errorf("Sigma 规则缺少 detection 段")
	}
	// 关联规则校验与默认值归一化
	if sy.Correlation != nil {
		c := sy.Correlation
		if c.Clue == nil && c.Confirm == nil {
			return nil, fmt.Errorf("correlation 段至少需要 clue（线索）或 confirm（确认）之一")
		}
		for name, st := range map[string]*sigmaStage{"clue": c.Clue, "confirm": c.Confirm} {
			if st == nil {
				continue
			}
			if st.Detection == nil || len(st.Detection) == 0 {
				return nil, fmt.Errorf("correlation.%s 缺少 detection 段", name)
			}
			if st.Logsource.Product == "" {
				if name == "clue" {
					st.Logsource.Product = "suricata"
				} else {
					st.Logsource.Product = "zeek"
				}
			}
		}
		if c.GroupBy == "" {
			c.GroupBy = "network.community_id"
		}
		if c.Required == "" {
			c.Required = "both"
		}
		switch c.Required {
		case "both", "clue", "confirm":
		default:
			return nil, fmt.Errorf("correlation.required 仅支持 both|clue|confirm，当前: %s", c.Required)
		}
		if c.Fallback == "" {
			c.Fallback = "none"
		}
		switch c.Fallback {
		case "none", "clue_only", "confirm_only":
		default:
			return nil, fmt.Errorf("correlation.fallback 仅支持 none|clue_only|confirm_only，当前: %s", c.Fallback)
		}
		if c.Confidence == "" {
			c.Confidence = sigmaConfidenceForLevel(sy.Level)
		}
		switch c.Confidence {
		case "low", "medium", "high":
		default:
			return nil, fmt.Errorf("correlation.confidence 仅支持 low|medium|high，当前: %s", c.Confidence)
		}
		if c.Timespan != "" && parseInterval(c.Timespan) <= 0 {
			return nil, fmt.Errorf("correlation.timespan 格式无效: %s", c.Timespan)
		}
	}
	if sy.Backend == "" {
		sy.Backend = "auto"
	}
	switch sy.Backend {
	case "eql", "esql", "auto":
	default:
		return nil, fmt.Errorf("backend 仅支持 eql|esql|auto，当前: %s", sy.Backend)
	}
	return &sy, nil
}

func sigmaConfidenceForLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// enrichSigmaRule 解析规则内容，填充类型/后端/关联元数据视图字段
func enrichSigmaRule(r *SigmaRule) {
	sy, err := parseSigma(r.Content)
	if err != nil {
		r.Type = "simple"
		r.Backend = "auto"
		return
	}
	r.Backend = sy.Backend
	if sy.Correlation == nil {
		r.Type = "simple"
		r.Correlation = nil
		return
	}
	r.Type = "correlation"
	cv := &correlationView{
		GroupBy:    sy.Correlation.GroupBy,
		Timespan:   sy.Correlation.Timespan,
		Required:   sy.Correlation.Required,
		Fallback:   sy.Correlation.Fallback,
		Confidence: sy.Correlation.Confidence,
	}
	if sy.Correlation.Clue != nil {
		cv.ClueProduct = sy.Correlation.Clue.Logsource.Product
	}
	if sy.Correlation.Confirm != nil {
		cv.ConfirmProduct = sy.Correlation.Confirm.Logsource.Product
	}
	r.Correlation = cv
}

func (s SigmaRule) load(id string) error {
	err := db.QueryRow(`SELECT id,title,content,category,product,service,level,status,schedule,last_run_at,created_at,updated_at
		FROM sigma_rules WHERE id=?`, id).
		Scan(&s.ID, &s.Title, &s.Content, &s.Category, &s.Product, &s.Service, &s.Level, &s.Status, &s.Schedule, &s.LastRunAt, &s.CreatedAt, &s.UpdatedAt)
	if err == nil {
		enrichSigmaRule(&s)
	}
	return err
}

func listSigmaRules() []SigmaRule {
	rows, err := db.Query(`SELECT id,title,content,category,product,service,level,status,schedule,last_run_at,builtin,created_at,updated_at FROM sigma_rules`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []SigmaRule{}
	for rows.Next() {
		var r SigmaRule
		var builtin int
		if err := rows.Scan(&r.ID, &r.Title, &r.Content, &r.Category, &r.Product, &r.Service, &r.Level, &r.Status, &r.Schedule, &r.LastRunAt, &builtin, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Builtin = builtin == 1
		enrichSigmaRule(&r)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// upsertSigmaRule 仅允许写入自定义规则（builtin=false）；内置规则由 importBuiltinSigma 维护
func upsertSigmaRule(r SigmaRule) error {
	return upsertSigmaRuleEx(r, false)
}

func upsertSigmaRuleEx(r SigmaRule, builtin bool) error {
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
	builtinV := 0
	if builtin {
		builtinV = 1
	}
	_, err = db.Exec(`INSERT INTO sigma_rules(id,title,content,category,product,service,level,status,schedule,builtin,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET title=excluded.title, content=excluded.content, category=excluded.category,
		product=excluded.product, service=excluded.service, level=excluded.level, status=excluded.status,
		schedule=excluded.schedule, builtin=excluded.builtin, updated_at=excluded.updated_at`,
		r.ID, r.Title, r.Content, r.Category, r.Product, r.Service, r.Level, r.Status, r.Schedule, builtinV, now, now)
	if err == nil {
		audit("sigma.upsert", r.ID, r.Title)
	}
	return err
}

// importBuiltinSigma 从产品规则库目录 /opt/so/builtin-sigma 导入内置 Sigma 规则：
// 内置规则仅可启停；产品升级时按 id 更新内容，但保留用户启停状态（status 不在更新列）
func importBuiltinSigma(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		r := SigmaRule{Content: string(data), Status: "disabled", Schedule: "5m"}
		sy, err := parseSigma(r.Content)
		if err != nil {
			log.Printf("warn: 内置 Sigma 规则 %s 解析失败: %v", name, err)
			continue
		}
		r.Title = sy.Title
		r.ID = sy.ID
		if r.ID == "" {
			sum := sha256.Sum256([]byte(r.Content))
			r.ID = "sigma-builtin-" + hex.EncodeToString(sum[:16])
		}
		if err := upsertSigmaRuleEx(r, true); err != nil {
			log.Printf("warn: 内置 Sigma 规则 %s 导入失败: %v", name, err)
			continue
		}
		count++
	}
	if count > 0 {
		log.Printf("已同步 %d 条内置 Sigma 规则（产品规则库）", count)
	}
	return nil
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

func builtinSigmaRule(id string) bool {
	var builtin int
	if err := db.QueryRow("SELECT builtin FROM sigma_rules WHERE id=?", id).Scan(&builtin); err != nil {
		return false
	}
	return builtin == 1
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
