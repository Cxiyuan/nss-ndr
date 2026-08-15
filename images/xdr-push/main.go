package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	XDR struct {
		Webhook struct {
			URL    string `yaml:"url"`
			Secret string `yaml:"secret"`
		} `yaml:"webhook"`
		TimeoutS      int      `yaml:"timeout_s"`
		PushIntervalS int      `yaml:"push_interval_s"`
		RetryMax      int      `yaml:"retry_max"`
		EventTypes    []string `yaml:"event_types"`
	} `yaml:"xdr"`
	Probe struct {
		ID string `yaml:"id"`
	} `yaml:"probe"`
}

const (
	confDir     = "/opt/so/conf"
	stateDir    = "/opt/so/state"
	cursorFile  = stateDir + "/xdr-push-cursor.json"
	dlqFile     = stateDir + "/xdr-push-dlq.jsonl"
	defaultHost = "https://nss-elasticsearch:9200"
)

var cfg Config

func loadConfig() {
	data, err := os.ReadFile(filepath.Join(confDir, "probe.yaml"))
	if err != nil {
		log.Fatalf("读取 probe.yaml 失败: %v", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("probe.yaml 解析失败: %v", err)
	}
	if cfg.XDR.Webhook.URL == "" {
		log.Printf("warn: xdr.webhook.url 未配置，推送暂停（本地仍留存告警）；请在 NDR 管理后台配置")
	}
	if cfg.XDR.PushIntervalS <= 0 {
		cfg.XDR.PushIntervalS = 2
	}
	if cfg.XDR.RetryMax <= 0 {
		cfg.XDR.RetryMax = 5
	}
	// 架构定位（2026-08-15）：NDR 只上报检测线索（suricata.alert）。
	// 威胁确认/关联分析由 XDR 下发分析任务，由 NDR 执行；不再推送最终告警。
	if len(cfg.XDR.EventTypes) == 0 {
		cfg.XDR.EventTypes = []string{"suricata.alert"}
	}
}

func main() {
	loadConfig()

	poller := NewPoller(os.Getenv("ES_HOST"), cfg)
	client := NewWebhookClient(cfg)

	cursor, err := loadCursor()
	if err != nil || cursor.TS == 0 {
		cursor = Cursor{TS: time.Now().Add(-time.Minute).UnixMilli(), ShardDoc: 0}
		log.Printf("初始化游标: %s", time.UnixMilli(cursor.TS).Format(time.RFC3339))
	}

	for {
		hits, next, err := poller.Fetch(cursor)
		if err != nil {
			log.Printf("warn: 拉取告警失败: %v", err)
		} else {
			if cfg.XDR.Webhook.URL == "" {
				log.Printf("warn: webhook 未配置，跳过 %d 条告警推送（本地已留存）", len(hits))
				goto sleep
			}
			for _, h := range hits {
				if err := client.Push(h); err != nil {
					log.Printf("warn: 推送失败 %s: %v（写入死信）", h.ID, err)
					_ = appendDLQ(h)
				}
			}
			if next != nil {
				cursor = *next
				_ = saveCursor(cursor)
			}
		}
	sleep:
		time.Sleep(time.Duration(cfg.XDR.PushIntervalS) * time.Second)
	}
}
