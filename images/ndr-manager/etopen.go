// ET Open 内置规则集管理：打包解压、版本化导入 SQLite、分类树统计、分类/单条启停
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	etopenVersionKey = "etopen.ruleset_version"
)

var (
	etopenDir      = envOr("NDR_ETOPEN_DIR", "/opt/so/etopen")
	etopenBundle   = filepath.Join(etopenDir, "etopen-rules.tar.gz")
	etopenMetaFile = filepath.Join(etopenDir, "categories.json")
	etopenRulesDir = filepath.Join(etopenDir, "rules")
	msgRe          = regexp.MustCompile(`msg:"((?:[^"\\]|\\.)*)"`)
)

type etopenCatMeta struct {
	Key    string `json:"key"`
	NameCN string `json:"name_cn"`
	DescCN string `json:"desc_cn"`
}

type etopenGroupMeta struct {
	Key        string          `json:"key"`
	Name       string          `json:"name"`
	Desc       string          `json:"desc"`
	Categories []etopenCatMeta `json:"categories"`
}

type etopenMeta struct {
	Version string            `json:"version"`
	Source  string            `json:"source"`
	SourceURL string          `json:"source_url"`
	License string            `json:"license"`
	Groups  []etopenGroupMeta `json:"groups"`
}

type etopenCatNode struct {
	Key          string `json:"key"`
	NameCN       string `json:"name_cn"`
	DescCN       string `json:"desc_cn"`
	File         string `json:"file"`
	Total        int    `json:"total"`
	EnabledCount int    `json:"enabled_count"`
	Enabled      bool   `json:"enabled"`
}

type etopenGroupNode struct {
	Key        string          `json:"key"`
	Name       string          `json:"name"`
	Desc       string          `json:"desc"`
	Categories []etopenCatNode `json:"categories"`
}

type etopenRulePage struct {
	Total int    `json:"total"`
	Rules []Rule `json:"rules"`
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadETOpenMeta() (*etopenMeta, error) {
	data, err := os.ReadFile(etopenMetaFile)
	if err != nil {
		return nil, err
	}
	var m etopenMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ensureETOpenExtracted 解压内置规则包到 rules 目录（镜像构建时未解压则以运行期兜底）
func ensureETOpenExtracted() error {
	if entries, err := os.ReadDir(etopenRulesDir); err == nil && len(entries) > 0 {
		return nil
	}
	if err := os.MkdirAll(etopenRulesDir, 0o750); err != nil {
		return err
	}
	f, err := os.Open(etopenBundle)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".rules") {
			continue
		}
		base := filepath.Base(hdr.Name)
		out, err := os.OpenFile(filepath.Join(etopenRulesDir, base), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	return nil
}

func etopenCategoryKey(file string) string {
	name := filepath.Base(file)
	name = strings.TrimSuffix(name, ".rules")
	name = strings.TrimPrefix(name, "emerging-")
	return name
}

// importETOpen 版本化导入：仅当内置包版本变化时全量重建（DELETE + INSERT OR IGNORE）
func importETOpen() error {
	if err := ensureETOpenExtracted(); err != nil {
		return fmt.Errorf("解压 ET Open 规则包失败: %w", err)
	}
	meta, err := loadETOpenMeta()
	if err != nil {
		return fmt.Errorf("读取 ET Open 分类元数据失败: %w", err)
	}
	var cur string
	_ = db.QueryRow("SELECT value FROM configs WHERE key=?", etopenVersionKey).Scan(&cur)
	if cur == meta.Version {
		return nil
	}

	files, err := filepath.Glob(filepath.Join(etopenRulesDir, "*.rules"))
	if err != nil {
		return err
	}
	sort.Strings(files)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM rules WHERE type='etopen'"); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO rules(id,name,rule,type,enabled,category,created_at,updated_at)
		VALUES(?,?,?,?,0,?,datetime('now'),datetime('now'))`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	total := 0
	for _, file := range files {
		cat := etopenCategoryKey(file)
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !isRuleAction(line) {
				continue
			}
			id := "et-" + cat + "-" + fmt.Sprint(hashString(line))
			name := extractRuleMsg(line)
			if name == "" {
				name = truncate(line, 60)
			}
			if _, err := stmt.Exec(id, name, line, "etopen", cat); err != nil {
				continue
			}
			total++
		}
	}
	if _, err := tx.Exec("INSERT INTO configs(key,value,updated_at) VALUES(?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
		etopenVersionKey, meta.Version); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	audit("etopen.import", meta.Version, fmt.Sprintf("导入 %d 条 ET Open 规则", total))
	return nil
}

func isRuleAction(line string) bool {
	for _, a := range []string{"alert ", "drop ", "pass ", "reject "} {
		if strings.HasPrefix(line, a) {
			return true
		}
	}
	return false
}

func extractRuleMsg(line string) string {
	m := msgRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// etopenTree 返回分类树（分组 -> 分类），含规则总数/启用数与中文说明
func etopenTree() ([]etopenGroupNode, error) {
	meta, err := loadETOpenMeta()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT category, COUNT(*), COALESCE(SUM(enabled),0) FROM rules WHERE type='etopen' GROUP BY category")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string][2]int{}
	for rows.Next() {
		var cat string
		var total, enabled int
		if err := rows.Scan(&cat, &total, &enabled); err != nil {
			continue
		}
		counts[cat] = [2]int{total, enabled}
	}

	groups := make([]etopenGroupNode, 0, len(meta.Groups))
	for _, g := range meta.Groups {
		node := etopenGroupNode{Key: g.Key, Name: g.Name, Desc: g.Desc}
		for _, c := range g.Categories {
			cnt := counts[c.Key]
			node.Categories = append(node.Categories, etopenCatNode{
				Key:          c.Key,
				NameCN:       c.NameCN,
				DescCN:       c.DescCN,
				File:         "emerging-" + c.Key + ".rules",
				Total:        cnt[0],
				EnabledCount: cnt[1],
				Enabled:      cnt[0] > 0 && cnt[1] == cnt[0],
			})
		}
		groups = append(groups, node)
	}
	return groups, nil
}

func etopenCategoryEnable(cat string, enabled bool) (int64, error) {
	v := 0
	if enabled {
		v = 1
	}
	res, err := db.Exec("UPDATE rules SET enabled=?, updated_at=datetime('now') WHERE type='etopen' AND category=?", v, cat)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	audit("etopen.category", cat, fmt.Sprintf("enabled=%v", enabled))
	return n, nil
}

func etopenSetRule(id string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := db.Exec("UPDATE rules SET enabled=?, updated_at=datetime('now') WHERE id=? AND type='etopen'", v, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("规则不存在或非 ET Open 规则")
	}
	audit("etopen.rule", id, fmt.Sprintf("enabled=%v", enabled))
	return nil
}

func etopenListRules(cat, q string, offset, limit int) (etopenRulePage, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var page etopenRulePage
	where := "WHERE type='etopen' AND category=?"
	args := []any{cat}
	if q != "" {
		where += " AND (name LIKE ? OR rule LIKE ?)"
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM rules "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := db.Query("SELECT id,name,rule,enabled FROM rules "+where+" ORDER BY rule LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &enabled); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		r.Type = "etopen"
		r.Category = cat
		page.Rules = append(page.Rules, r)
	}
	return page, nil
}
