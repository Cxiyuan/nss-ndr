// Sigma -> EQL 转换器：调用 pySigma（sigma CLI，对齐 SO 标准做法）
// 转换：sigma convert -t eql -p sigma_so_pipeline.yaml /dev/stdin
package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

type sigmaQuery struct {
	Indexes []string       `json:"indexes"`
	EQL     string         `json:"eql"`
	ESQL    string         `json:"esql,omitempty"`
	Backend string         `json:"backend,omitempty"`
	Filter  map[string]any `json:"filter,omitempty"`
}

var sigmaPipeline = envOr("NDR_SIGMA_PIPELINE", "/opt/ndr-manager/sigma_so_pipeline.yaml")

// buildSigmaQuery 用 pySigma（sigma CLI）把 Sigma 规则转换为 EQL 查询；
// backend 为 esql/auto 时额外尝试 ES|QL 转换（失败不阻断，执行仍走 EQL）。
func buildSigmaQuery(content string) (*sigmaQuery, error) {
	sy, err := parseSigma(content)
	if err != nil {
		return nil, err
	}
	eql, err := convertSigma(content, "eql")
	if err != nil {
		return nil, err
	}
	if eql == "" {
		return nil, fmt.Errorf("sigma 转换结果为空")
	}

	sq := &sigmaQuery{EQL: eql, ESQL: "", Backend: sy.Backend}
	if sy.Backend != "eql" {
		if esql, cerr := convertSigma(content, "esql"); cerr == nil {
			sq.ESQL = esql
		} else if sy.Backend == "esql" {
			return nil, fmt.Errorf("ES|QL 转换失败: %v", cerr)
		} else {
			// auto：ES|QL 不可用时静默回退 EQL
			log.Printf("warn: ES|QL 转换不可用（%v），规则回退 EQL", cerr)
		}
	}
	// logsource -> 索引与 event.dataset 过滤
	ls := sy.Logsource
	switch strings.ToLower(ls.Product) {
	case "zeek":
		sq.Indexes = []string{"logs-zeek-so"}
	case "suricata":
		sq.Indexes = []string{"logs-suricata.alerts-so"}
	default:
		sq.Indexes = []string{"logs-zeek-so", "logs-suricata.alerts-so"}
	}
	ds := ""
	// service 更具体，优先映射到对应数据集；category 作为兜底
	switch strings.ToLower(ls.Service) {
	case "dns":
		ds = "zeek.dns"
	case "http":
		ds = "zeek.http"
	case "ssl", "tls":
		ds = "zeek.ssl"
	case "smb":
		ds = "zeek.smb"
	case "smb_files":
		ds = "zeek.smb_files"
	case "smb_mapping":
		ds = "zeek.smb_mapping"
	case "ntlm":
		ds = "zeek.ntlm"
	case "file":
		ds = "zeek.files"
	}
	if ds == "" {
		switch strings.ToLower(ls.Category) {
		case "network_connection", "network":
			ds = "zeek.conn"
		case "dns":
			ds = "zeek.dns"
		case "web", "http":
			ds = "zeek.http"
		case "tls", "ssl":
			ds = "zeek.ssl"
		case "file":
			ds = "zeek.files"
		case "smb":
			ds = "zeek.smb"
		case "smb_files":
			ds = "zeek.smb_files"
		case "smb_mapping":
			ds = "zeek.smb_mapping"
		case "ntlm":
			ds = "zeek.ntlm"
		}
	}
	if ds != "" {
		sq.Filter = map[string]any{"term": map[string]any{"event.dataset": ds}}
	}
	return sq, nil
}

// convertSigma 调用 pySigma（sigma CLI）把 Sigma 规则内容转换为指定格式（eql | esql）
func convertSigma(content, format string) (string, error) {
	cmd := exec.Command("sigma", "convert", "-t", format,
		"-p", sigmaPipeline, "/dev/stdin")
	cmd.Stdin = bytes.NewReader([]byte(content))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sigma %s 转换失败: %v: %s", format, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// buildStageQuery 把关联规则中的单个阶段（clue/confirm）渲染成独立 Sigma 文档后转换
func buildStageQuery(stage sigmaStage, title, ruleID string) (*sigmaQuery, error) {
	doc := map[string]any{
		"title":  title,
		"id":     ruleID,
		"status": "test",
		"level":  "medium",
		"logsource": map[string]any{
			"category": stage.Logsource.Category,
			"product":  stage.Logsource.Product,
			"service":  stage.Logsource.Service,
		},
		"detection": stage.Detection,
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("阶段 Sigma 文档渲染失败: %w", err)
	}
	return buildSigmaQuery(string(data))
}
