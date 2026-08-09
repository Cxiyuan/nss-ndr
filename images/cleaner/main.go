package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Probe struct {
		MinFreeGB            int    `yaml:"min_free_gb"`
		DiskPressureThreshold int    `yaml:"disk_pressure_threshold"`
		CleanupInterval      string `yaml:"cleanup_interval"`
	} `yaml:"probe"`
	Suricata struct {
		Pcap struct {
			RetentionDays  int    `yaml:"retention_days"`
			StorageLimitGB int    `yaml:"storage_limit_gb"`
			FileSizeMB     int    `yaml:"file_size_mb"`
		} `yaml:"pcap"`
		Eve struct {
			RetentionDays int `yaml:"retention_days"`
		} `yaml:"eve"`
	} `yaml:"suricata"`
	Zeek struct {
		HistoryRetentionDays int `yaml:"history_retention_days"`
		Extraction           struct {
			MaxDays int `yaml:"max_days"`
		} `yaml:"extraction"`
	} `yaml:"zeek"`
}

const (
	confDir    = "/opt/so/conf"
	stateFile  = "/opt/so/state/cleaner-status.json"
	nsmDir     = "/nsm"
	suripcap   = nsmDir + "/suripcap"
	suricataEv = nsmDir + "/suricata"
	zeekLogs   = nsmDir + "/zeek/logs"
	zeekExt    = nsmDir + "/zeek/extracted/complete"
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
	if cfg.Probe.MinFreeGB == 0 {
		cfg.Probe.MinFreeGB = 20
	}
	if cfg.Probe.DiskPressureThreshold == 0 {
		cfg.Probe.DiskPressureThreshold = 90
	}
}

type status struct {
	Time             string   `json:"time"`
	FSUsagePct       int      `json:"fs_usage_pct"`
	SuripcapBytes    int64    `json:"suripcap_bytes"`
	RemovedFiles     int      `json:"removed_files"`
	RemovedBytes     int64    `json:"removed_bytes"`
	PressureTriggered bool    `json:"pressure_triggered"`
	Errors           []string `json:"errors,omitempty"`
}

func main() {
	loadConfig()
	st := status{Time: time.Now().UTC().Format(time.RFC3339)}

	// 1) 常规清理
	removedFiles, removedBytes, errs := cleanupRoutine()
	st.RemovedFiles = removedFiles
	st.RemovedBytes = removedBytes
	st.Errors = errs

	// 2) 磁盘压力兜底
	usage := fsUsagePct(nsmDir)
	st.FSUsagePct = usage
	if usage > cfg.Probe.DiskPressureThreshold {
		st.PressureTriggered = true
		log.Printf("磁盘用量 %d%% 超过阈值 %d%%，触发压力清理", usage, cfg.Probe.DiskPressureThreshold)
		cleanUnderPressure()
		usage = fsUsagePct(nsmDir)
		st.FSUsagePct = usage
	}
	st.SuripcapBytes = dirSize(suripcap)

	// 3) 低水位告警
	freeGB := fsFreeGB(nsmDir)
	if int(freeGB) < cfg.Probe.MinFreeGB {
		log.Printf("WARN: /nsm 剩余 %.1fGB 低于 min_free_gb=%d", freeGB, cfg.Probe.MinFreeGB)
	}

	saveStatus(st)
	log.Printf("清理完成：文件 %d 个，释放 %.2fGB，/nsm 用量 %d%%", removedFiles, float64(removedBytes)/1e9, usage)
}

// cleanupRoutine 按留存天数/容量阈值清理 eve、zeek 历史、提取文件、全包
func cleanupRoutine() (int, int64, []string) {
	var errs []string
	totalFiles, totalBytes := 0, int64(0)

	delEve, delBytes := removeOldFiles(suricataEv, "eve-*.json", cfg.Suricata.Eve.RetentionDays)
	totalFiles += delEve
	totalBytes += delBytes

	delZeek, zbytes := removeOldDirs(zeekLogs, cfg.Zeek.HistoryRetentionDays)
	totalFiles += delZeek
	totalBytes += zbytes

	delExt, ebytes := removeOldFiles(zeekExt, "*", cfg.Zeek.Extraction.MaxDays)
	totalFiles += delExt
	totalBytes += ebytes

	// 全包：先按天数，再按总量上限
	pcapDays := cfg.Suricata.Pcap.RetentionDays
	if pcapDays > 0 {
		delP, pbytes := removeOldFiles(suripcap, "so-pcap.*", pcapDays)
		totalFiles += delP
		totalBytes += pbytes
	}
	limit := int64(cfg.Suricata.Pcap.StorageLimitGB) * 1e9
	if limit > 0 {
		for dirSize(suripcap) > limit {
			removed := removeOldest(suripcap, "so-pcap.*")
			if removed == 0 {
				errs = append(errs, "全包超限但无可删文件")
				break
			}
			totalFiles++
			totalBytes += removed
		}
	}
	return totalFiles, totalBytes, errs
}

// removeOldFiles 删除 mtime 早于 N 天的匹配文件（含 .gz）
func removeOldFiles(dir, pattern string, days int) (int, int64) {
	if days <= 0 {
		return 0, 0
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	matches2, _ := filepath.Glob(filepath.Join(dir, pattern+".gz"))
	matches = append(matches, matches2...)
	count, bytes := 0, int64(0)
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || info.IsDir() {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		sz := info.Size()
		if err := os.Remove(m); err == nil {
			count++
			bytes += sz
			log.Printf("清理 %s（%.1fMB）", m, float64(sz)/1e6)
		}
	}
	return count, bytes
}

// removeOldDirs 删除 mtime 早于 N 天的目录（zeek 轮转历史）
func removeOldDirs(dir string, days int) (int, int64) {
	if days <= 0 {
		return 0, 0
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	count, bytes := 0, int64(0)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "current" || name == "spool" || strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		sz := dirSize(filepath.Join(dir, name))
		if err := os.RemoveAll(filepath.Join(dir, name)); err == nil {
			count++
			bytes += sz
			log.Printf("清理目录 %s（%.1fMB）", name, float64(sz)/1e6)
		}
	}
	return count, bytes
}

// removeOldest 删除目录中最旧的一个匹配文件，返回释放字节数
func removeOldest(dir, pattern string) int64 {
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	if len(matches) == 0 {
		return 0
	}
	sort.Slice(matches, func(i, j int) bool {
		ii, _ := os.Stat(matches[i])
		jj, _ := os.Stat(matches[j])
		return ii.ModTime().Before(jj.ModTime())
	})
	info, err := os.Stat(matches[0])
	if err != nil {
		return 0
	}
	if err := os.Remove(matches[0]); err != nil {
		return 0
	}
	log.Printf("超限清理 %s（%.1fMB）", matches[0], float64(info.Size())/1e6)
	return info.Size()
}

// cleanUnderPressure 磁盘压力兜底：循环删最旧，顺序 zeek 历史 → 提取 → 全包
func cleanUnderPressure() {
	for _, target := range []struct {
		dir, pattern string
	}{{zeekLogs, "*"}, {zeekExt, "*"}, {suripcap, "so-pcap.*"}} {
		for fsUsagePct(nsmDir) > cfg.Probe.DiskPressureThreshold {
			var removed int64
			if target.dir == zeekLogs {
				removed = removeOldestDir(target.dir)
			} else {
				removed = removeOldest(target.dir, target.pattern)
			}
			if removed == 0 {
				break
			}
		}
	}
}

func removeOldestDir(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var cands []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "current" && e.Name() != "spool" && !strings.HasPrefix(e.Name(), ".") {
			cands = append(cands, filepath.Join(dir, e.Name()))
		}
	}
	if len(cands) == 0 {
		return 0
	}
	sort.Slice(cands, func(i, j int) bool {
		ii, _ := os.Stat(cands[i])
		jj, _ := os.Stat(cands[j])
		return ii.ModTime().Before(jj.ModTime())
	})
	sz := dirSize(cands[0])
	_ = os.RemoveAll(cands[0])
	log.Printf("压力清理目录 %s（%.1fMB）", cands[0], float64(sz)/1e6)
	return sz
}

func dirSize(dir string) int64 {
	out, err := exec.Command("du", "-sb", dir).Output()
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n
}

func fsUsagePct(dir string) int {
	out, err := exec.Command("df", "-P", dir).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 5 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
	return n
}

func fsFreeGB(dir string) float64 {
	out, err := exec.Command("df", "-P", dir).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0
	}
	avail, _ := strconv.ParseInt(fields[3], 10, 64)
	return float64(avail) / 1e9
}

func saveStatus(st status) {
	data, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o750); err == nil {
		_ = os.WriteFile(stateFile, data, 0o640)
	}
}
