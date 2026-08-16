// ES 初始化（原 es-init 镜像功能并入 manager）：等待 ES 就绪、创建应用用户（幂等）、
// 导入 ingest pipelines / ILM 策略 / 索引模板。周期执行以支持配置变更自动恢复。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	esInitPipelinesDir = "/opt/ndr-manager/pipelines" // 镜像内置（COPY images/es-init/pipelines）
)

func startESInit() {
	go func() {
		time.Sleep(2 * time.Second)
		for {
			if err := esInitOnce(); err != nil {
				log.Printf("warn: ES 初始化失败: %v，30s 后重试", err)
				time.Sleep(30 * time.Second)
				continue
			}
			log.Printf("ES 初始化完成")
			time.Sleep(300 * time.Second) // 周期复查，支持 ES 重启/配置变更自动恢复
		}
	}()
}

func esInitOnce() error {
	// 1) 等待 ES 就绪且安全插件可认证（elastic 认证成功才继续，避免初始化时序 401）
	esURL := os.Getenv("ES_HOST")
	if esURL == "" {
		esURL = "http://nss-elasticsearch:9200"
	}
	elasticPass := os.Getenv("ELASTIC_PASSWORD")
	adminAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:"+elasticPass))
	if err := waitESReady(esURL, adminAuth); err != nil {
		return err
	}

	// 2) 创建/校验应用用户（幂等：密码正确则跳过，避免每次重启重置造成瞬时认证失败）
	type appUser struct{ name, pass, roles string }
	users := []appUser{
		{"filebeat", os.Getenv("FB_PASSWORD"), "superuser"},
		{"xdr-push", os.Getenv("XDR_PASSWORD"), "superuser"},
	}
	for _, u := range users {
		if u.pass == "" {
			continue
		}
		if err := ensureUser(esURL, u.name, u.pass, u.roles); err != nil {
			return fmt.Errorf("用户 %s 处理失败: %w", u.name, err)
		}
	}

	// 3) 导入 pipelines / ILM / 索引模板
	files, err := os.ReadDir(esInitPipelinesDir)
	if err != nil {
		return fmt.Errorf("读取 pipelines 目录失败: %w", err)
	}
	for _, e := range files {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(esInitPipelinesDir, name)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".json"):
			// ingest pipeline：zeek.conn.json -> PUT /_ingest/pipeline/zeek.conn
			pn := strings.TrimSuffix(name, ".json")
			if err := esPut(esURL, adminAuth, "/_ingest/pipeline/"+pn, data); err != nil {
				return fmt.Errorf("pipeline %s: %w", pn, err)
			}
		case strings.HasSuffix(name, ".json.ilmpolicy"):
			pn := strings.TrimSuffix(name, ".json.ilmpolicy")
			if err := esPut(esURL, adminAuth, "/_ilm/policy/"+pn, data); err != nil {
				return fmt.Errorf("ILM %s: %w", pn, err)
			}
		case strings.HasSuffix(name, ".json.template"):
			pn := strings.TrimSuffix(name, ".json.template")
			if err := esPut(esURL, adminAuth, "/_index_template/"+pn, data); err != nil {
				return fmt.Errorf("索引模板 %s: %w", pn, err)
			}
		}
	}
	return nil
}

func waitESReady(esURL, adminAuth string) error {
	for {
		// 先等 health
		code, err := esReq(http.MethodGet, esURL+"/_cluster/health", adminAuth, nil)
		if err != nil || code >= 300 {
			time.Sleep(5 * time.Second)
			continue
		}
		// 再等安全插件可认证（elastic 密码生效）
		code, err = esReq(http.MethodGet, esURL+"/_security/_authenticate", adminAuth, nil)
		if err == nil && code < 300 {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
}

// ensureUser 校验用户密码是否已是期望值；不一致则创建/更新（幂等）
func ensureUser(esURL, name, pass, roles string) error {
	userAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+pass))
	code, err := esReq(http.MethodGet, esURL+"/_security/_authenticate", userAuth, nil)
	if err == nil && code < 300 {
		return nil // 密码已正确，跳过
	}
	body, _ := json.Marshal(map[string]any{"password": pass, "roles": []string{roles}})
	code, err = esReq(http.MethodPut, esURL+"/_security/user/"+name, basicAuthHeader(esURL), body)
	if err != nil || code >= 300 {
		return fmt.Errorf("创建用户 %s 失败 (%d %v)", name, code, err)
	}
	log.Printf("已创建/更新用户 %s", name)
	return nil
}

func esPut(esURL, adminAuth, path string, data []byte) error {
	code, err := esReq(http.MethodPut, esURL+path, adminAuth, data)
	if err != nil || code >= 300 {
		return fmt.Errorf("PUT %s -> %d %v", path, code, err)
	}
	return nil
}

func esReq(method, url, auth string, body []byte) (int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func basicAuthHeader(esURL string) string {
	_ = esURL
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:"+os.Getenv("ELASTIC_PASSWORD")))
}

// esInitPipelineNames 供诊断/测试使用：列出将导入的 pipeline 名
func esInitPipelineNames() []string {
	files, err := os.ReadDir(esInitPipelinesDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range files {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ".json"):
			names = append(names, strings.TrimSuffix(n, ".json"))
		case strings.HasSuffix(n, ".json.ilmpolicy"):
			names = append(names, strings.TrimSuffix(n, ".json.ilmpolicy")+" (ILM)")
		case strings.HasSuffix(n, ".json.template"):
			names = append(names, strings.TrimSuffix(n, ".json.template")+" (template)")
		}
	}
	sort.Strings(names)
	return names
}
