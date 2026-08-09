// 配置渲染引擎：FullConfig -> ConfigMap data（等价 scripts/render-configs.py）
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"math"
	"strings"
)

//go:embed all:templates
var tplFS embed.FS

type renderedData struct {
	Data map[string]string
}

func renderAll(c FullConfig) (*renderedData, error) {
	if c.Probe.Interface == "" {
		return nil, fmt.Errorf("镜像口未配置：probe.interface 必须按部署服务器实际网卡填写")
	}
	threads := c.Suricata.AfPacketThreads
	if threads <= 0 {
		threads = 4
	}
	fileSizeMB := c.Suricata.Pcap.FileSizeMB
	if fileSizeMB <= 0 {
		fileSizeMB = 1000
	}
	storageGB := c.Suricata.Pcap.StorageLimitGB
	if storageGB <= 0 {
		storageGB = 500
	}
	maxFiles := int(math.Ceil(float64(storageGB*1000) / float64(fileSizeMB) / float64(threads)))
	if maxFiles < 1 {
		maxFiles = 1
	}

	ctx := map[string]string{
		"INTERFACE":             c.Probe.Interface,
		"THREADS":               fmt.Sprint(threads),
		"HOME_NET":              "'[" + strings.Join(c.Probe.HomeNet, ",") + "]'",
		"EXTERNAL_NET":          c.Probe.ExternalNet,
		"PCAP_ENABLED":          boolToYesNo(c.Suricata.Pcap.Enabled),
		"PCAP_FILE_SIZE_MB":     fmt.Sprint(fileSizeMB),
		"PCAP_COMPRESSION":      c.Suricata.Pcap.Compression,
		"PCAP_MAX_FILES":        fmt.Sprint(maxFiles),
		"WORKERS":               fmt.Sprint(c.Zeek.Workers),
		"BUFFER_SIZE":           c.Zeek.BufferSize,
		"LOG_ROTATION_INTERVAL": fmt.Sprint(c.Zeek.LogRotationIntervalS),
	}
	var networks strings.Builder
	for _, n := range c.Probe.HomeNet {
		networks.WriteString(fmt.Sprintf("%s Private_IP_Space\n", n))
	}
	ctx["ZEEK_NETWORKS"] = strings.TrimSuffix(networks.String(), "\n")

	data := map[string]string{}
	templates := map[string]string{
		"suricata.yaml": "templates/suricata.yaml",
		"threshold.conf": "templates/threshold.conf",
		"local.zeek":    "templates/local.zeek",
		"node.cfg":      "templates/node.cfg",
		"zeekctl.cfg":   "templates/zeekctl.cfg",
		"networks.cfg":  "templates/networks.cfg",
		"filebeat.yml":  "templates/filebeat.yml",
		"kibana.yml":    "templates/kibana.yml",
	}
	for key, rel := range templates {
		content, err := tplFS.ReadFile(rel)
		if err != nil {
			return nil, err
		}
		s := string(content)
		for k, v := range ctx {
			s = strings.ReplaceAll(s, "${"+k+"}", v)
		}
		data[key] = s
	}

	// zeek policy 脚本（扁平化 key，与 ConfigMap 约定一致）
	_ = fs.WalkDir(tplFS, "templates/policy/securityonion", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, rerr := tplFS.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel := strings.TrimPrefix(path, "templates/policy/securityonion/")
		data["policy_securityonion_"+strings.ReplaceAll(rel, "/", "_")] = string(content)
		return nil
	})

	data["bpf"] = c.Probe.BPF
	data["sensor_id"] = c.Probe.ID
	data["interface"] = c.Probe.Interface
	data["all-rulesets.rules"] = renderRulesContent()
	fullYAML, _ := yamlMarshalFull(c)
	data["probe.yaml"] = fullYAML
	return &renderedData{Data: data}, nil
}

func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// renderRulesContent 生成 all-rulesets.rules（启用规则 + threshold 段）
func renderRulesContent() string {
	var sb strings.Builder
	for _, r := range store.EnabledRules() {
		sb.WriteString(strings.TrimSpace(r.Rule))
		sb.WriteString("\n")
		if strings.TrimSpace(r.Threshold) != "" {
			sb.WriteString(strings.TrimSpace(r.Threshold))
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
