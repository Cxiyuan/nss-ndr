// Kibana 反向代理：探针 UI 内嵌 NDR 看板（免二次登录）
// 后端用 elastic 账号登录 Kibana 维护 sid 会话，代理 /kibana/* 到 Kibana(basePath=/kibana)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"
)

const kibanaInternalBase = "http://nss-kibana:5601"

var kibanaProxy = &kibanaReverseProxy{}

type kibanaReverseProxy struct {
	mu        sync.Mutex
	sid       string
	lastLogin time.Time
}

// ensureLogin 用 KIBANA_PROXY_USERNAME/PASSWORD 登录 Kibana，缓存 sid cookie
func (p *kibanaReverseProxy) ensureLogin() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sid != "" && time.Since(p.lastLogin) < 20*time.Minute {
		return nil
	}
	user := os.Getenv("KIBANA_PROXY_USERNAME")
	pass := os.Getenv("KIBANA_PROXY_PASSWORD")
	if user == "" || pass == "" {
		return fmt.Errorf("KIBANA_PROXY_USERNAME/PASSWORD 未配置")
	}
	body, _ := json.Marshal(map[string]any{
		"providerType": "basic",
		"providerName": "basic",
		"currentURL":   "/",
		"params": map[string]string{
			"username": user,
			"password": pass,
		},
	})
	req, err := http.NewRequest(http.MethodPost, kibanaInternalBase+"/internal/security/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == "sid" {
			p.sid = c.Value
			p.lastLogin = time.Now()
			return nil
		}
	}
	return fmt.Errorf("kibana 登录失败: HTTP %d", resp.StatusCode)
}

// ServeHTTP 反向代理 /kibana/* 到 Kibana（保留 /kibana basePath 前缀）
func (p *kibanaReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := p.ensureLogin(); err != nil {
		writeErr(w, http.StatusBadGateway, "Kibana 会话初始化失败: "+err.Error())
		return
	}
	target, err := url.Parse(kibanaInternalBase)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.Header.Set("Cookie", "sid="+p.sid)
		req.Header.Set("kbn-xsrf", "true")
	}
	proxy.ServeHTTP(w, r)
}
