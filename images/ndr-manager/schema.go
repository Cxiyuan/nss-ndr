// 配置调控参数 Schema：把可变配置项定义成表单字段，UI 表单化编辑
// 恒定不变的配置（镜像版本、内部链路、证书等）不在此暴露
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type FieldSpec struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"` // number|string|bool|select|list|secret
	Unit    string   `json:"unit,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
	Step    float64  `json:"step,omitempty"`
	Options []string `json:"options,omitempty"`
	Help    string   `json:"help,omitempty"`
	Default any      `json:"default,omitempty"`
	Group   string   `json:"group"`
	Order   int      `json:"order"`
	Section string   `json:"-"`
}

type GroupSpec struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Order int    `json:"order"`
}

func num(v float64) *float64 { return &v }

// fieldDefs 全部可变配置项定义
var fieldDefs = []FieldSpec{
	// 采集
	{Key: "probe.interface", Label: "镜像口（抓包网卡）", Type: "string", Group: "capture", Order: 1, Section: cfgProbe,
		Help: "服务器实际抓包网卡名，如 enp5s0 / eth1；留空无法下发"},
	{Key: "probe.home_net", Label: "内网网段 HOME_NET", Type: "list", Group: "capture", Order: 2, Section: cfgProbe,
		Help: "每行一个 CIDR，如 10.0.0.0/8"},
	{Key: "probe.external_net", Label: "外网网段 EXTERNAL_NET", Type: "string", Group: "capture", Order: 3, Section: cfgProbe},
	{Key: "probe.bpf", Label: "BPF 过滤表达式", Type: "string", Group: "capture", Order: 4, Section: cfgProbe,
		Help: "可选，如 not port 22"},
	{Key: "suricata.af_packet_threads", Label: "Suricata 抓包线程数", Type: "number", Min: num(1), Max: num(16), Step: 1,
		Unit: "线程", Group: "capture", Order: 5, Section: cfgSuricata, Help: "建议 ≤ 服务器核数"},
	{Key: "zeek.workers", Label: "Zeek worker 数", Type: "number", Min: num(1), Max: num(16), Step: 1,
		Unit: "worker", Group: "capture", Order: 6, Section: cfgZeek, Help: "建议 ≤ 服务器核数"},
	{Key: "zeek.buffer_size", Label: "Zeek 抓包缓冲区", Type: "string", Group: "capture", Order: 7, Section: cfgZeek,
		Help: "如 128*1024*1024"},
	{Key: "zeek.log_rotation_interval_s", Label: "Zeek 日志轮转间隔", Type: "number", Min: num(60), Max: num(86400), Step: 60,
		Unit: "秒", Group: "capture", Order: 8, Section: cfgZeek},

	// 留存
	{Key: "suricata.pcap.enabled", Label: "启用全包留存", Type: "bool", Group: "retention", Order: 10, Section: cfgSuricata},
	{Key: "suricata.pcap.file_size_mb", Label: "全包单文件大小", Type: "number", Min: num(100), Max: num(4096), Step: 100,
		Unit: "MB", Group: "retention", Order: 11, Section: cfgSuricata},
	{Key: "suricata.pcap.compression", Label: "全包压缩", Type: "select", Options: []string{"none", "lz4"},
		Group: "retention", Order: 12, Section: cfgSuricata},
	{Key: "suricata.pcap.retention_days", Label: "全包留存天数", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 13, Section: cfgSuricata},
	{Key: "suricata.pcap.storage_limit_gb", Label: "全包存储上限", Type: "number", Min: num(10), Max: num(2000), Step: 10,
		Unit: "GB", Group: "retention", Order: 14, Section: cfgSuricata},
	{Key: "suricata.eve.retention_days", Label: "EVE 日志留存天数", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 15, Section: cfgSuricata},
	{Key: "zeek.history_retention_days", Label: "Zeek 历史留存天数", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 16, Section: cfgZeek},
	{Key: "zeek.extraction.max_days", Label: "Zeek 提取文件留存天数", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 17, Section: cfgZeek},
	{Key: "strelka.retention.processed_days", Label: "Strelka 已扫描文件留存", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 18, Section: cfgStrelka},
	{Key: "strelka.retention.history_days", Label: "Strelka 去重记录留存", Type: "number", Min: num(1), Max: num(30), Step: 1,
		Unit: "天", Group: "retention", Order: 19, Section: cfgStrelka},
	{Key: "strelka.retention.log_days", Label: "Strelka 扫描日志留存", Type: "number", Min: num(1), Max: num(365), Step: 1,
		Unit: "天", Group: "retention", Order: 20, Section: cfgStrelka},
	{Key: "probe.min_free_gb", Label: "磁盘低水位告警", Type: "number", Min: num(5), Max: num(200), Step: 5,
		Unit: "GB", Group: "retention", Order: 21, Section: cfgProbe},
	{Key: "probe.disk_pressure_threshold", Label: "磁盘压力清理阈值", Type: "number", Min: num(50), Max: num(99), Step: 1,
		Unit: "%", Group: "retention", Order: 22, Section: cfgProbe},
	{Key: "probe.cleanup_interval", Label: "清理扫描周期", Type: "string", Group: "retention", Order: 23, Section: cfgProbe,
		Help: "如 1h / 30m"},
	{Key: "elasticsearch.retention.metadata_days", Label: "ES 元数据留存天数", Type: "number", Min: num(1), Max: num(3650), Step: 1,
		Unit: "天", Group: "retention", Order: 24, Section: cfgElasticsearch},
	{Key: "elasticsearch.retention.alerts_days", Label: "ES 告警留存天数", Type: "number", Min: num(1), Max: num(3650), Step: 1,
		Unit: "天", Group: "retention", Order: 25, Section: cfgElasticsearch},

	// XDR 推送
	{Key: "xdr.webhook.url", Label: "Webhook 地址", Type: "string", Group: "xdr", Order: 40, Section: cfgXdr},
	{Key: "xdr.webhook.secret", Label: "HMAC 签名密钥", Type: "secret", Group: "xdr", Order: 41, Section: cfgXdr},
	{Key: "xdr.timeout_s", Label: "推送超时", Type: "number", Min: num(1), Max: num(120), Step: 1, Unit: "秒",
		Group: "xdr", Order: 42, Section: cfgXdr},
	{Key: "xdr.push_interval_s", Label: "推送周期", Type: "number", Min: num(1), Max: num(60), Step: 1, Unit: "秒",
		Group: "xdr", Order: 43, Section: cfgXdr},
	{Key: "xdr.retry_max", Label: "最大重试次数", Type: "number", Min: num(0), Max: num(10), Step: 1,
		Group: "xdr", Order: 44, Section: cfgXdr},
	{Key: "xdr.event_types", Label: "推送事件白名单", Type: "list", Group: "xdr", Order: 45, Section: cfgXdr,
		Help: "每行一个，如 suricata.alert / zeek.notice"},

	// 系统
	{Key: "elasticsearch.heap_gb", Label: "ES 堆内存", Type: "number", Min: num(1), Max: num(16), Step: 1, Unit: "GB",
		Group: "system", Order: 50, Section: cfgElasticsearch, Help: "修改后 ES 会重启，短暂中断写入"},
	{Key: "strelka.enabled", Label: "启用 Strelka 文件分析", Type: "bool", Group: "system", Order: 51, Section: cfgStrelka},
	{Key: "strelka.backend_replicas", Label: "Strelka 扫描副本数", Type: "number", Min: num(1), Max: num(8), Step: 1,
		Group: "system", Order: 52, Section: cfgStrelka},
}

// 资源类组件：key -> (kind, workload, container)
var resourceTargets = map[string][3]string{
	"suricata":           {"daemonsets", "nss-suricata", "suricata"},
	"zeek":               {"daemonsets", "nss-zeek", "zeek"},
	"filebeat":           {"daemonsets", "nss-filebeat", "filebeat"},
	"elasticsearch":      {"deployments", "nss-elasticsearch", "elasticsearch"},
	"ndr-manager":        {"deployments", "nss-ndr-manager", "ndr-manager"},
	"xdr-push":           {"deployments", "nss-xdr-push", "xdr-push"},
	"filecheck":          {"deployments", "nss-strelka-filecheck", "filecheck"},
	"strelka-backend":    {"deployments", "nss-strelka-backend", "backend"},
	"strelka-manager":    {"deployments", "nss-strelka-manager", "manager"},
	"strelka-frontend":   {"deployments", "nss-strelka-frontend", "frontend"},
	"strelka-filestream": {"deployments", "nss-strelka-filestream", "filestream"},
}

// 资源字段：resources.<组件>.<requests|limits>.<cpu|memory>
func resourceFieldDefs() []FieldSpec {
	var defs []FieldSpec
	comps := make([]string, 0, len(resourceTargets))
	for k := range resourceTargets {
		comps = append(comps, k)
	}
	sort.Strings(comps)
	order := 60
	for _, c := range comps {
		label := map[string]string{
			"suricata": "检测引擎", "zeek": "网络元数据", "filebeat": "日志采集",
			"elasticsearch": "数据存储",
			"ndr-manager":   "管理后台", "xdr-push": "告警推送",
			"filecheck": "文件检查", "strelka-backend": "Strelka 扫描",
			"strelka-manager": "Strelka 管理", "strelka-frontend": "Strelka 前端",
			"strelka-filestream": "Strelka 文件流",
		}[c]
		for _, slot := range []string{"requests", "limits"} {
			for _, r := range []string{"cpu", "memory"} {
				defs = append(defs, FieldSpec{
					Key:     fmt.Sprintf("resources.%s.%s.%s", c, slot, r),
					Label:   fmt.Sprintf("%s %s %s", label, slot, r),
					Type:    "string",
					Group:   "resources",
					Order:   order,
					Section: cfgResources,
					Help:    "k8s 资源写法，如 cpu: 100m/1，内存: 256Mi/4Gi",
				})
				order++
			}
		}
	}
	return defs
}

func allFieldDefs() []FieldSpec {
	return append(fieldDefs, resourceFieldDefs()...)
}

var configGroups = []GroupSpec{
	{Key: "capture", Label: "采集", Order: 1},
	{Key: "retention", Label: "留存", Order: 2},
	{Key: "detections", Label: "检测", Order: 3},
	{Key: "xdr", Label: "告警推送", Order: 4},
	{Key: "system", Label: "系统", Order: 5},
	{Key: "resources", Label: "资源限制", Order: 6},
}

func defaultResources() map[string]any {
	return map[string]any{
		"suricata":           map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "256Mi"}, "limits": map[string]any{"cpu": "4", "memory": "4Gi"}},
		"zeek":               map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "256Mi"}, "limits": map[string]any{"cpu": "4", "memory": "4Gi"}},
		"filebeat":           map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "128Mi"}, "limits": map[string]any{"cpu": "1", "memory": "512Mi"}},
		"elasticsearch":      map[string]any{"requests": map[string]any{"cpu": "200m", "memory": "2Gi"}, "limits": map[string]any{"cpu": "2", "memory": "4Gi"}},
		"ndr-manager":        map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "256Mi"}, "limits": map[string]any{"cpu": "500m", "memory": "512Mi"}},
		"xdr-push":           map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "128Mi"}, "limits": map[string]any{"cpu": "500m", "memory": "256Mi"}},
		"filecheck":          map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "128Mi"}, "limits": map[string]any{"cpu": "200m", "memory": "512Mi"}},
		"strelka-backend":    map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "256Mi"}, "limits": map[string]any{"cpu": "2", "memory": "4Gi"}},
		"strelka-manager":    map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "64Mi"}, "limits": map[string]any{"cpu": "200m", "memory": "256Mi"}},
		"strelka-frontend":   map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "128Mi"}, "limits": map[string]any{"cpu": "500m", "memory": "512Mi"}},
		"strelka-filestream": map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "128Mi"}, "limits": map[string]any{"cpu": "500m", "memory": "512Mi"}},
	}
}

// loadResources 返回 resources YAML 解析后的 map
func loadResources() (map[string]any, error) {
	val, err := getSection(cfgResources)
	if err != nil {
		return defaultResources(), nil
	}
	m := map[string]any{}
	if strings.TrimSpace(val) != "" {
		if err := yaml.Unmarshal([]byte(val), &m); err != nil {
			return defaultResources(), nil
		}
	}
	return m, nil
}

// saveResources 保存资源配置（YAML）
func saveResources(res map[string]any, comment string) error {
	data, err := yaml.Marshal(res)
	if err != nil {
		return err
	}
	return saveSection(cfgResources, string(data), comment)
}

// configAsMap 把 FullConfig 转成嵌套 map（用于按路径取值）
func configAsMap(c FullConfig) (map[string]any, error) {
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// getPath 从嵌套 map 按点分路径取值
func getPath(m map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var cur any = m
	for _, p := range parts {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath 在嵌套 map 中按点分路径写值（自动建中间节点）
func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = v
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

// apiConfigSchema GET /api/config/schema：分组 + 字段定义 + 当前值
func apiConfigSchema(w http.ResponseWriter, _ *http.Request) {
	c, err := loadFull()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cm, err := configAsMap(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	res, _ := loadResources()

	fields := make([]map[string]any, 0, len(fieldDefs)+len(resourceTargets)*4)
	for _, f := range allFieldDefs() {
		out := map[string]any{
			"key": f.Key, "label": f.Label, "type": f.Type, "group": f.Group,
			"order": f.Order, "help": f.Help, "default": f.Default,
		}
		if f.Unit != "" {
			out["unit"] = f.Unit
		}
		if f.Min != nil {
			out["min"] = *f.Min
		}
		if f.Max != nil {
			out["max"] = *f.Max
		}
		if f.Step != 0 {
			out["step"] = f.Step
		}
		if len(f.Options) > 0 {
			out["options"] = f.Options
		}
		if f.Section == cfgResources {
			if v, ok := getPath(res, strings.TrimPrefix(f.Key, "resources.")); ok {
				out["value"] = v
			} else if v, ok := getPath(defaultResources(), strings.TrimPrefix(f.Key, "resources.")); ok {
				out["value"] = v
			}
		} else if v, ok := getPath(cm, f.Key); ok {
			out["value"] = v
		}
		fields = append(fields, out)
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i]["order"].(int) < fields[j]["order"].(int)
	})
	writeJSON(w, http.StatusOK, map[string]any{"groups": configGroups, "fields": fields})
}

// apiSaveFormConfig PUT /api/config：保存表单字段（校验后按 section 落库）
func apiSaveFormConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Fields  map[string]any `json:"fields"`
		Comment string         `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if body.Fields == nil {
		writeErr(w, http.StatusBadRequest, "缺少 fields")
		return
	}

	// 1) 校验字段并构建各 section 的嵌套 map
	c, err := loadFull()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cm, err := configAsMap(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	res, _ := loadResources()
	defs := allFieldDefs()
	byKey := map[string]FieldSpec{}
	for _, f := range defs {
		byKey[f.Key] = f
	}

	sections := map[string]map[string]any{}
	for key, raw := range body.Fields {
		f, ok := byKey[key]
		if !ok {
			writeErr(w, http.StatusBadRequest, "未知配置项: "+key)
			return
		}
		val, err := validateField(f, raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, key+": "+err.Error())
			return
		}
		if f.Section == cfgResources {
			setPath(res, strings.TrimPrefix(key, "resources."), val)
		} else {
			if sections[f.Section] == nil {
				// 初始化：以该 section 现值打底，避免未提交字段丢失
				if secVal, ok := getPath(cm, f.Section); ok {
					if mm, ok := secVal.(map[string]any); ok {
						sections[f.Section] = mm
					}
				}
				if sections[f.Section] == nil {
					sections[f.Section] = map[string]any{}
				}
			}
			setPath(sections[f.Section], strings.TrimPrefix(key, f.Section+"."), val)
		}
	}

	// 2) 逐 section 序列化保存
	for sec, m := range sections {
		data, err := yaml.Marshal(m)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := saveSection(sec, string(data), body.Comment); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if len(sections) > 0 || true {
		if err := saveResources(res, body.Comment); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// validateField 按类型/范围校验并把值转成目标类型
func validateField(f FieldSpec, raw any) (any, error) {
	switch f.Type {
	case "number":
		fv, ok := toFloat(raw)
		if !ok {
			return nil, fmt.Errorf("必须是数字")
		}
		if f.Min != nil && fv < *f.Min {
			return nil, fmt.Errorf("不能小于 %v", *f.Min)
		}
		if f.Max != nil && fv > *f.Max {
			return nil, fmt.Errorf("不能大于 %v", *f.Max)
		}
		return int(math.Round(fv)), nil
	case "bool":
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("必须是布尔值")
		}
		return b, nil
	case "select":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("必须是字符串")
		}
		for _, o := range f.Options {
			if s == o {
				return s, nil
			}
		}
		return nil, fmt.Errorf("必须为 %s 之一", strings.Join(f.Options, "/"))
	case "list":
		switch v := raw.(type) {
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				out = append(out, fmt.Sprint(item))
			}
			return out, nil
		case string:
			var out []string
			for _, line := range strings.Split(v, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					out = append(out, line)
				}
			}
			return out, nil
		default:
			return nil, fmt.Errorf("列表格式错误")
		}
	default: // string / secret
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("必须是字符串")
		}
		if f.Key == "probe.interface" && strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("镜像口不能为空")
		}
		return s, nil
	}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}
