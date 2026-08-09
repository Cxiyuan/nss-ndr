// Sigma -> Elasticsearch Query DSL 转换器（对齐 SO 的 pySigma 语义，支持网络类子集）
package main

import (
	"fmt"
	"strings"
)

// sigmaFieldMap：Sigma 常用字段 -> 我们的 ECS 字段（zeek/suricata）
var sigmaFieldMap = map[string]string{
	"DestinationIp":           "destination.ip",
	"DestinationAddress":      "destination.ip",
	"dest_ip":                 "destination.ip",
	"SourceIp":                "source.ip",
	"SourceAddress":           "source.ip",
	"src_ip":                  "source.ip",
	"DestinationPort":         "destination.port",
	"dest_port":               "destination.port",
	"SourcePort":              "source.port",
	"src_port":                "source.port",
	"Protocol":                "network.transport",
	"proto":                   "network.transport",
	"dns.query_name":          "dns.question.name",
	"queryName":               "dns.question.name",
	"dns.query.type":          "dns.question.type",
	"http.url":                "url.full",
	"http.uri":                "http.request.uri",
	"uri":                     "url.full",
	"http.method":             "http.request.method",
	"method":                  "http.request.method",
	"http.host":               "url.domain",
	"host":                    "server.domain",
	"hostname":                "server.domain",
	"DestinationHostname":     "server.domain",
	"DestinationUserName":     "destination.user.name",
	"http.user_agent":         "user_agent.original",
	"user_agent":              "user_agent.original",
	"http.response.status_code": "http.response.status_code",
}

type sigmaQuery struct {
	Indexes []string       `json:"indexes"`
	Query   map[string]any `json:"query"`
	Filter  map[string]any `json:"filter,omitempty"`
}

// buildSigmaQuery 把 Sigma 规则内容转换为 ES 查询
func buildSigmaQuery(content string) (*sigmaQuery, error) {
	sy, err := parseSigma(content)
	if err != nil {
		return nil, err
	}
	cond, ok := sy.Detection["condition"].(string)
	if !ok || strings.TrimSpace(cond) == "" {
		return nil, fmt.Errorf("Sigma 规则缺少 condition")
	}

	selections := map[string]map[string]any{}
	for name, v := range sy.Detection {
		if name == "condition" {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			selections[name] = m
		}
	}
	if len(selections) == 0 {
		return nil, fmt.Errorf("Sigma 规则没有可用的 selection")
	}

	query, err := parseSigmaCondition(cond, selections)
	if err != nil {
		return nil, err
	}

	sq := &sigmaQuery{Query: query}
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

// ---------- condition 解析 ----------

type condNode struct {
	op    string // and | or | not | ref
	kids  []condNode
	name  string
	level int // "N of" 语义：0=all,1=any,>1=N of
}

func parseSigmaCondition(cond string, sel map[string]map[string]any) (map[string]any, error) {
	names := make([]string, 0, len(sel))
	for n := range sel {
		names = append(names, n)
	}
	root, err := parseCondExpr(cond, names)
	if err != nil {
		return nil, err
	}
	return condToQuery(root, sel)
}

// parseCondExpr 解析 Sigma condition 表达式（简化递归下降）
func parseCondExpr(expr string, names []string) (condNode, error) {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimPrefix(expr, "(")
	expr = strings.TrimSuffix(expr, ")")
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)

	// all of X / any of X / 1 of X / N of them
	if strings.HasPrefix(lower, "all of ") {
		return refNode(expr[7:], 0, names), nil
	}
	if strings.HasPrefix(lower, "any of ") {
		return refNode(expr[7:], 1, names), nil
	}
	if strings.HasPrefix(lower, "1 of ") {
		return refNode(expr[5:], 1, names), nil
	}
	// N of them（如 2 of them）
	if n, ok := numOfThem(expr); ok {
		return condNode{op: "ref", name: "*", level: n}, nil
	}

	// 顶层 " and " / " or " 拆分（不处理嵌套括号的复杂场景）
	if idx := topLevelSplit(lower, " and "); idx >= 0 {
		l, err := parseCondExpr(expr[:idx], names)
		if err != nil {
			return condNode{}, err
		}
		r, err := parseCondExpr(expr[idx+5:], names)
		if err != nil {
			return condNode{}, err
		}
		return condNode{op: "and", kids: []condNode{l, r}}, nil
	}
	if idx := topLevelSplit(lower, " or "); idx >= 0 {
		l, err := parseCondExpr(expr[:idx], names)
		if err != nil {
			return condNode{}, err
		}
		r, err := parseCondExpr(expr[idx+4:], names)
		if err != nil {
			return condNode{}, err
		}
		return condNode{op: "or", kids: []condNode{l, r}}, nil
	}
	if strings.HasPrefix(lower, "not ") {
		k, err := parseCondExpr(expr[4:], names)
		if err != nil {
			return condNode{}, err
		}
		return condNode{op: "not", kids: []condNode{k}}, nil
	}
	// 单个 selection 名
	if contains(names, expr) {
		return refNode(expr, 0, names), nil
	}
	return condNode{}, fmt.Errorf("无法解析 condition: %q", expr)
}

func refNode(nameSpec string, level int, names []string) condNode {
	nameSpec = strings.TrimSpace(nameSpec)
	return condNode{op: "ref", name: nameSpec, level: level}
}

func numOfThem(expr string) (int, bool) {
	parts := strings.SplitN(strings.TrimSpace(expr), " ", 3)
	if len(parts) == 3 && parts[1] == "of" && parts[2] == "them" {
		n := 0
		if _, err := fmt.Sscanf(parts[0], "%d", &n); err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

func topLevelSplit(lower, sep string) int {
	depth := 0
	for i := 0; i+len(sep) <= len(lower); i++ {
		switch lower[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && strings.HasPrefix(lower[i:], sep) {
			return i
		}
	}
	return -1
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func condToQuery(n condNode, sel map[string]map[string]any) (map[string]any, error) {
	switch n.op {
	case "and":
		q := map[string]any{"bool": map[string]any{"filter": []any{}}}
		filters := q["bool"].(map[string]any)["filter"].([]any)
		for _, k := range n.kids {
			sub, err := condToQuery(k, sel)
			if err != nil {
				return nil, err
			}
			filters = append(filters, sub)
		}
		q["bool"].(map[string]any)["filter"] = filters
		return q, nil
	case "or":
		should := []any{}
		for _, k := range n.kids {
			sub, err := condToQuery(k, sel)
			if err != nil {
				return nil, err
			}
			should = append(should, sub)
		}
		return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}, nil
	case "not":
		sub, err := condToQuery(n.kids[0], sel)
		if err != nil {
			return nil, err
		}
		return map[string]any{"bool": map[string]any{"must_not": []any{sub}}}, nil
	case "ref":
		return refToQuery(n.name, n.level, sel)
	}
	return nil, fmt.Errorf("未知条件节点: %s", n.op)
}

func refToQuery(nameSpec string, level int, sel map[string]map[string]any) (map[string]any, error) {
	// 解析 name 列表（支持 * 通配）
	matched := []string{}
	for n := range sel {
		if nameSpec == "*" || nameSpec == "them" || strings.HasSuffix(nameSpec, "*") && strings.HasPrefix(n, strings.TrimSuffix(nameSpec, "*")) || nameSpec == n {
			matched = append(matched, n)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("selection 未匹配: %q", nameSpec)
	}
	queries := []any{}
	for _, n := range matched {
		queries = append(queries, selectionToQuery(sel[n]))
	}
	if len(queries) == 1 && level <= 1 {
		return queries[0].(map[string]any), nil
	}
	// level: 0=all(AND) 1=any(OR) >1=N of(minimum_should_match)
	b := map[string]any{"bool": map[string]any{}}
	if level == 0 {
		b["bool"].(map[string]any)["filter"] = queries
	} else {
		b["bool"].(map[string]any)["should"] = queries
		if level > 1 {
			b["bool"].(map[string]any)["minimum_should_match"] = level
		} else {
			b["bool"].(map[string]any)["minimum_should_match"] = 1
		}
	}
	return b, nil
}

// selectionToQuery 把单个 selection（field->value 映射）转 ES query
func selectionToQuery(sel map[string]any) map[string]any {
	conds := []any{}
	for rawField, v := range sel {
		field, mod := splitFieldModifier(rawField)
		field = mapField(field)
		conds = append(conds, valueToQuery(field, v, mod))
	}
	if len(conds) == 1 {
		return conds[0].(map[string]any)
	}
	return map[string]any{"bool": map[string]any{"filter": conds}}
}

func splitFieldModifier(f string) (string, string) {
	if i := strings.Index(f, "|"); i >= 0 {
		return f[:i], f[i+1:]
	}
	return f, ""
}

func mapField(f string) string {
	if m, ok := sigmaFieldMap[f]; ok {
		return m
	}
	return f
}

func valueToQuery(field string, v any, mod string) map[string]any {
	switch val := v.(type) {
	case []any:
		terms := []any{}
		for _, item := range val {
			if s, ok := item.(string); ok && (mod == "contains" || mod == "startswith" || mod == "endswith" || strings.Contains(s, "*")) {
				return wildcardQuery(field, val, mod)
			}
			terms = append(terms, item)
		}
		return map[string]any{"terms": map[string]any{field: terms}}
	case []string:
		return map[string]any{"terms": map[string]any{field: toAnySlice(val)}}
	case map[string]any:
		// selection 值本身是 map（少见），递归处理
		sub := []any{}
		for k, sv := range val {
			sub = append(sub, valueToQuery(k, sv, ""))
		}
		return map[string]any{"bool": map[string]any{"filter": sub}}
	default:
		s := fmt.Sprint(v)
		switch mod {
		case "contains":
			return wildcardOne(field, "*"+s+"*")
		case "startswith":
			return wildcardOne(field, s+"*")
		case "endswith":
			return wildcardOne(field, "*"+s)
		case "re":
			return map[string]any{"regexp": map[string]any{field: s}}
		case "cidr":
			// 简化：CIDR 前缀转通配（IPv4 前 3 段）
			parts := strings.Split(s, "/")
			if len(parts) == 2 {
				return wildcardOne(field, parts[0]+"*")
			}
			return wildcardOne(field, s)
		}
		if strings.Contains(s, "*") {
			return wildcardOne(field, s)
		}
		// 数字字段传数值
		if isNumeric(s) {
			return map[string]any{"term": map[string]any{field: num(s)}}
		}
		return map[string]any{"term": map[string]any{field: s}}
	}
}

func wildcardQuery(field string, val []any, mod string) map[string]any {
	should := []any{}
	for _, item := range val {
		s := fmt.Sprint(item)
		switch mod {
		case "contains":
			should = append(should, wildcardOne(field, "*"+s+"*"))
		case "startswith":
			should = append(should, wildcardOne(field, s+"*"))
		case "endswith":
			should = append(should, wildcardOne(field, "*"+s))
		default:
			should = append(should, wildcardOne(field, s))
		}
	}
	return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}
}

func wildcardOne(field, pattern string) map[string]any {
	return map[string]any{"wildcard": map[string]any{field: pattern}}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func num(s string) any {
	var i int64
	var f float64
	if _, err := fmt.Sscanf(s, "%d", &i); err == nil {
		return i
	}
	_, _ = fmt.Sscanf(s, "%f", &f)
	return f
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
