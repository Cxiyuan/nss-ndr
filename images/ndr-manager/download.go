// NDR 文件下载端点：用于 XDR 离线取证 / 二次分析
//   GET /api/pcap/{name}   — 下载 suricata pcap 全包
//   GET /api/file/{md5}    — 下载 Zeek 提取 / Strelka 已扫描的样本（按 MD5 查找）
//
// 鉴权：探针用户会话（requireAuth，不接受 XDR 任务 token）
//                因为下载是面向人工取证需求，XDR 平台下载走 /api/xdr/* 内部接口
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	pcapDir            = "/nsm/suripcap"
	zeekExtractedDir    = "/nsm/zeek/extracted/complete"
	strelkaProcessedDir = "/nsm/strelka/processed"
	maxDownloadSize     = 2 << 30 // 2 GB（pcap 可能很大）
)

var (
	// pcap 文件名规则：so-pcap.<iso8601>.<thread>.pcap
	pcapNameRe = regexp.MustCompile(`^so-pcap\.\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\.pcap$`)
	// MD5 32 / SHA256 64 字符（hex）
	hashRe = regexp.MustCompile(`^[a-fA-F0-9]{32}([a-fA-F0-9]{32})?$`)
)

// isFile 判断路径是常规文件
func isFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// streamFile 流式发送文件（避免大文件全读内存）
func streamFile(w http.ResponseWriter, path, attachmentName string) {
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在: "+filepath.Base(path))
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+attachmentName+`"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	if _, err := io.Copy(w, f); err != nil {
		// 客户端中途断开是常见情况，静默处理
		return
	}
	audit("file.download", filepath.Base(path), fmt.Sprintf("size=%d", stat.Size()))
}

// apiPcapDownload GET /api/pcap/{name}
//   路径校验：仅允许 basename，禁止 ../，必须匹配 so-pcap.*.pcap 格式
//   鉴权：用户会话（XDR token 无效）
func apiPcapDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || strings.ContainsAny(name, "/\\") || name != filepath.Base(name) || !pcapNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "非法 pcap 文件名（需匹配 so-pcap.<iso-timestamp>.<thread>.pcap）")
		return
	}
	path := filepath.Join(pcapDir, name)
	stat, err := os.Stat(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在或已清理")
		return
	}
	if stat.Size() > maxDownloadSize {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("文件超 2GB 上限（实际 %d 字节）", stat.Size()))
		return
	}
	streamFile(w, path, name)
}

// apiFileDownload GET /api/file/{md5}
//   路径校验：md5 32 字符 / sha256 64 字符（hex）
//   查找顺序：先 Zeek 提取目录（同一份原始文件），再 Strelka 已扫描目录
//   鉴权：用户会话
func apiFileDownload(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("md5")
	if hash == "" || !hashRe.MatchString(strings.ToLower(hash)) {
		writeErr(w, http.StatusBadRequest, "非法 hash（需 32 字符 MD5 或 64 字符 SHA256）")
		return
	}
	hash = strings.ToLower(hash)

	// 查找候选目录（先 Zeek 提取的原始文件，再 Strelka 已扫描副本）
	dirs := []struct {
		dir   string
		tag   string
	}{
		{zeekExtractedDir, "zeek.extracted"},
		{strelkaProcessedDir, "strelka.processed"},
	}
	var found, sourceTag string
search:
	for _, d := range dirs {
		// 先匹配精确名（Zeek 命名为 <md5>.<ext>）
		matches, _ := filepath.Glob(filepath.Join(d.dir, hash+".*"))
		for _, m := range matches {
			if isFile(m) {
				found = m
				sourceTag = d.tag
				break search
			}
		}
		// 再匹配纯 md5（Strelka 目录可能用纯 md5 命名）
		if isFile(filepath.Join(d.dir, hash)) {
			found = filepath.Join(d.dir, hash)
			sourceTag = d.tag
			break
		}
	}

	if found == "" {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("未找到 %s 对应的文件（已清理或从未提取）", hash))
		return
	}

	stat, err := os.Stat(found)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stat.Size() > maxDownloadSize {
		writeErr(w, http.StatusRequestEntityTooLarge, "文件过大")
		return
	}

	audit("file.download", filepath.Base(found), fmt.Sprintf("hash=%s source=%s size=%d", hash, sourceTag, stat.Size()))
	streamFile(w, found, filepath.Base(found))
}

// sha256Hex 保留作为后续完整性校验（计算文件 SHA256 用于校验）
func sha256Hex(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

var _ = sha256Hex // 保留避免 unused 警告
