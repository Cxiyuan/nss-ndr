// Sigma -> EQL 转换器：调用 pySigma（sigma CLI，对齐 SO 标准做法）
// 转换：sigma convert -t eql -p sigma_so_pipeline.yaml /dev/stdin
package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type sigmaQuery struct {
	Indexes []string       `json:"indexes"`
	EQL     string         `json:"eql"`
	Filter  map[string]any `json:"filter,omitempty"`
}

const sigmaPipeline = "/opt/ndr-manager/sigma_so_pipeline.yaml"

// buildSigmaQuery 用 pySigma（sigma CLI）把 Sigma 规则转换为 EQL 查询
func buildSigmaQuery(content string) (*sigmaQuery, error) {
	sy, err := parseSigma(content)
	if err != nil {
		return nil, err
	}
	// 调用 sigma CLI 转换（pySigma 标准）
	cmd := exec.Command("sigma", "convert", "-t", "eql",
		"-p", sigmaPipeline, "/dev/stdin")
	cmd.Stdin = bytes.NewReader([]byte(content))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sigma 转换失败: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	eql := strings.TrimSpace(string(out))
	if eql == "" {
		return nil, fmt.Errorf("sigma 转换结果为空")
	}

	sq := &sigmaQuery{EQL: eql}
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
	}
	if ds == "" {
		switch strings.ToLower(ls.Service) {
		case "dns":
			ds = "zeek.dns"
		case "http":
			ds = "zeek.http"
		case "ssl", "tls":
			ds = "zeek.ssl"
		}
	}
	if ds != "" {
		sq.Filter = map[string]any{"term": map[string]any{"event.dataset": ds}}
	}
	return sq, nil
}
