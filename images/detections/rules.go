package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Rule      string    `json:"rule"`
	Threshold string    `json:"threshold,omitempty"` // 可选：内嵌 threshold/suppress 配置
	Type      string    `json:"type"` // custom | builtin
	Enabled   bool      `json:"enabled"`
	Category  string    `json:"category,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	rules map[string]Rule
}

func NewStore(path string) *Store {
	return &Store{path: path, rules: map[string]Rule{}}
}

func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.rules)
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o640)
}

func (s *Store) List() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) Get(id string) (Rule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	return r, ok
}

func (s *Store) Upsert(r Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.UpdatedAt = time.Now().UTC()
	s.rules[r.ID] = r
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	return true
}

func (s *Store) SetEnabled(id string, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return false
	}
	r.Enabled = enabled
	r.UpdatedAt = time.Now().UTC()
	s.rules[id] = r
	return true
}

// ImportBuiltins 首次导入内置规则集（默认禁用）
func (s *Store) ImportBuiltins(dir string) error {
	if _, ok := s.Get("so_filters"); ok {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(e.Name(), ".rules")
		s.Upsert(Rule{
			ID: name, Name: name, Rule: string(data),
			Type: "builtin", Enabled: false, CreatedAt: now,
		})
		log.Printf("导入内置规则集: %s", name)
	}
	return nil
}

// Apply 渲染 all-rulesets.rules 并触发 suricata 热加载
func (s *Store) Apply() error {
	if err := s.Save(); err != nil {
		log.Printf("warn: 状态保存失败: %v", err)
	}
	var sb strings.Builder
	for _, r := range s.List() {
		if !r.Enabled || strings.TrimSpace(r.Rule) == "" {
			continue
		}
		sb.WriteString("# === " + r.Name + " ===\n")
		text := injectThreshold(r.Rule, r.Threshold)
		sb.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			sb.WriteString("\n")
		}
	}
	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		return fmt.Errorf("创建规则目录失败: %w", err)
	}
	if err := os.WriteFile(rulesFile, []byte(sb.String()), 0o640); err != nil {
		return fmt.Errorf("写入规则文件失败: %w", err)
	}
	log.Printf("已渲染 %s（%d 字节）", rulesFile, sb.Len())
	return reloadSuricata()
}

// injectThreshold 把阈值/抑制配置内嵌到规则末尾括号前（suricata 原生支持，reload 即生效）
func injectThreshold(rule, threshold string) string {
	if strings.TrimSpace(threshold) == "" {
		return rule
	}
	idx := strings.LastIndex(rule, ")")
	if idx < 0 {
		return rule
	}
	return rule[:idx] + "threshold: " + strings.TrimSpace(threshold) + "; " + rule[idx:]
}
