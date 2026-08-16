package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 组件配置分组（configs 表的 key）
const (
	cfgProbe         = "probe"
	cfgSuricata      = "suricata"
	cfgZeek          = "zeek"
	cfgElasticsearch = "elasticsearch"
	cfgXdr           = "xdr"
	cfgStrelka       = "strelka"
	cfgDetections    = "detections"
	cfgResources     = "resources"
)

// FullConfig 是 probe.yaml 的完整结构（渲染与展示用）
type FullConfig struct {
	Probe struct {
		ID                    string   `yaml:"id"`
		Interface             string   `yaml:"interface"`
		HomeNet               []string `yaml:"home_net"`
		ExternalNet           string   `yaml:"external_net"`
		BPF                   string   `yaml:"bpf"`
		MinFreeGB             int      `yaml:"min_free_gb"`
		DiskPressureThreshold int      `yaml:"disk_pressure_threshold"`
		CleanupInterval       string   `yaml:"cleanup_interval"`
	} `yaml:"probe"`
	Suricata struct {
		Enabled         bool `yaml:"enabled"`
		AfPacketThreads int  `yaml:"af_packet_threads"`
		Pcap            struct {
			Enabled        bool   `yaml:"enabled"`
			FileSizeMB     int    `yaml:"file_size_mb"`
			Compression    string `yaml:"compression"`
			RetentionDays  int    `yaml:"retention_days"`
			StorageLimitGB int    `yaml:"storage_limit_gb"`
		} `yaml:"pcap"`
		Eve struct {
			RetentionDays int `yaml:"retention_days"`
		} `yaml:"eve"`
	} `yaml:"suricata"`
	Zeek struct {
		Enabled              bool   `yaml:"enabled"`
		Workers              int    `yaml:"workers"`
		BufferSize           string `yaml:"buffer_size"`
		LogRotationIntervalS int    `yaml:"log_rotation_interval_s"`
		HistoryRetentionDays int    `yaml:"history_retention_days"`
		Extraction           struct {
			MaxDays int `yaml:"max_days"`
		} `yaml:"extraction"`
	} `yaml:"zeek"`
	Strelka struct {
		Enabled         bool `yaml:"enabled"`
		BackendReplicas int  `yaml:"backend_replicas"`
		Retention       struct {
			ProcessedDays int `yaml:"processed_days"`
			HistoryDays   int `yaml:"history_days"`
			LogDays       int `yaml:"log_days"`
		} `yaml:"retention"`
	} `yaml:"strelka"`
	Elasticsearch struct {
		HeapGB    int `yaml:"heap_gb"`
		Retention struct {
			MetadataDays int `yaml:"metadata_days"`
			AlertsDays   int `yaml:"alerts_days"`
		} `yaml:"retention"`
	} `yaml:"elasticsearch"`
	Detections struct {
		DefaultRuleset string `yaml:"default_ruleset"`
	} `yaml:"detections"`
	Xdr struct {
		Webhook struct {
			URL    string `yaml:"url"`
			Secret string `yaml:"secret"`
		} `yaml:"webhook"`
		// TaskToken XDR 下发分析任务的 Bearer 令牌（NDR 作为执行者接收任务）
		TaskToken string `yaml:"task_token"`
		// AgentURL 本地分析 Agent 服务地址（Agent 通过 MCP 工具分析 XDR 任务）
		AgentURL      string   `yaml:"agent_url"`
		AgentEnabled  bool     `yaml:"agent_enabled"`
		TimeoutS      int      `yaml:"timeout_s"`
		PushIntervalS int      `yaml:"push_interval_s"`
		RetryMax      int      `yaml:"retry_max"`
		EventTypes    []string `yaml:"event_types"`
	} `yaml:"xdr"`
}

func defaultConfig() FullConfig {
	var c FullConfig
	c.Probe.ID = "nss-001"
	c.Probe.Interface = ""
	c.Probe.HomeNet = []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
	c.Probe.ExternalNet = "any"
	c.Probe.MinFreeGB = 20
	c.Probe.DiskPressureThreshold = 90
	c.Probe.CleanupInterval = "1h"
	c.Suricata.Enabled = true
	c.Suricata.AfPacketThreads = 2
	c.Suricata.Pcap.Enabled = true
	c.Suricata.Pcap.FileSizeMB = 1000
	c.Suricata.Pcap.Compression = "none"
	c.Suricata.Pcap.RetentionDays = 7
	c.Suricata.Pcap.StorageLimitGB = 500
	c.Suricata.Eve.RetentionDays = 7
	c.Zeek.Enabled = true
	c.Zeek.Workers = 2
	c.Zeek.BufferSize = "128*1024*1024"
	c.Zeek.LogRotationIntervalS = 3600
	c.Zeek.HistoryRetentionDays = 30
	c.Zeek.Extraction.MaxDays = 7
	c.Strelka.Enabled = true
	c.Strelka.BackendReplicas = 1
	c.Strelka.Retention.ProcessedDays = 30
	c.Strelka.Retention.HistoryDays = 2
	c.Strelka.Retention.LogDays = 30
	c.Elasticsearch.HeapGB = 2
	c.Elasticsearch.Retention.MetadataDays = 60
	c.Elasticsearch.Retention.AlertsDays = 365
	c.Detections.DefaultRuleset = "none"
	c.Xdr.TimeoutS = 10
	c.Xdr.PushIntervalS = 2
	c.Xdr.RetryMax = 5
	c.Xdr.EventTypes = []string{"suricata.alert"}
	c.Xdr.AgentURL = "http://nss-ndr-agent:8081/analyze"
	c.Xdr.AgentEnabled = true
	return c
}

// seedConfig 优先从挂载的 ConfigMap（/opt/so/conf/probe.yaml）读取部署实况作为种子，
// 保证 UI 首次打开显示的是当前实际配置（interface 等部署参数），而不是空默认值
func seedConfig() FullConfig {
	c := defaultConfig()
	data, err := os.ReadFile(filepath.Join(confDir, "probe.yaml"))
	if err != nil {
		return c
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c
	}
	return c
}

func ensureDefaults() error {
	for _, key := range []string{cfgProbe, cfgSuricata, cfgZeek, cfgElasticsearch, cfgXdr, cfgStrelka, cfgDetections, cfgResources} {
		var exists int
		err := db.QueryRow("SELECT 1 FROM configs WHERE key=?", key).Scan(&exists)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// 初始化默认值（优先用部署实况 seed）
		var val string
		if key == cfgResources {
			data, err := yaml.Marshal(defaultResources())
			if err != nil {
				return err
			}
			val = string(data)
		} else {
			v, err := marshalSection(key, seedConfig())
			if err != nil {
				return err
			}
			val = v
		}
		if _, err := db.Exec("INSERT INTO configs(key, value) VALUES(?,?)", key, val); err != nil {
			return err
		}
	}
	return nil
}

// marshalSection 把 FullConfig 的某个 section 序列化为 YAML
func marshalSection(key string, c FullConfig) (string, error) {
	var v any
	switch key {
	case cfgProbe:
		v = c.Probe
	case cfgSuricata:
		v = c.Suricata
	case cfgZeek:
		v = c.Zeek
	case cfgStrelka:
		v = c.Strelka
	case cfgElasticsearch:
		v = c.Elasticsearch
	case cfgXdr:
		v = c.Xdr
	case cfgDetections:
		v = c.Detections
	case cfgResources:
		return "", errors.New("resources 不参与 FullConfig 序列化")
	default:
		return "", errors.New("未知配置分组: " + key)
	}
	data, err := yaml.Marshal(v)
	return string(data), err
}

// loadFull 从 SQLite 加载全部配置合并为 FullConfig
func loadFull() (FullConfig, error) {
	c := defaultConfig()
	rows, err := db.Query("SELECT key, value FROM configs")
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, val string
		if err := rows.Scan(&key, &val); err != nil {
			return c, err
		}
		var target any
		switch key {
		case cfgProbe:
			target = &c.Probe
		case cfgSuricata:
			target = &c.Suricata
		case cfgZeek:
			target = &c.Zeek
		case cfgStrelka:
			target = &c.Strelka
		case cfgElasticsearch:
			target = &c.Elasticsearch
		case cfgXdr:
			target = &c.Xdr
		case cfgDetections:
			target = &c.Detections
		default:
			continue
		}
		if err := yaml.Unmarshal([]byte(val), target); err != nil {
			return c, err
		}
	}
	return c, nil
}

// getSection 返回某组件的配置（原始 YAML 字符串）
func getSection(key string) (string, error) {
	var val string
	err := db.QueryRow("SELECT value FROM configs WHERE key=?", key).Scan(&val)
	return val, err
}

// saveSection 保存某组件配置（记录版本 + 审计）
func saveSection(key, value, comment string) error {
	if strings.TrimSpace(value) != "" {
		var check any
		if err := yaml.Unmarshal([]byte(value), &check); err != nil {
			return errors.New("YAML 解析失败: " + err.Error())
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO configs(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
		key, value, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO config_versions(key, value, action, comment) VALUES(?,?,?,?)",
		key, value, "update", comment); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO audit(action, target, detail) VALUES(?,?,?)",
		"config.update", key, comment); err != nil {
		return err
	}
	return tx.Commit()
}

// 序列化工具
func toJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func yamlMarshalFull(c FullConfig) (string, error) {
	data, err := yaml.Marshal(c)
	return string(data), err
}
