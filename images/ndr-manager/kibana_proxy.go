// Kibana 反向代理：探针 UI 内嵌 NDR 看板（免二次登录）
// 代理 /kibana/* 到 Kibana(basePath=/kibana)，每请求注入 Basic 认证头。
// 说明：Kibana 9 默认限制 internal API（/internal/security/login 被禁），
// 因此不走"登录取 sid"流程，改为直接使用 KIBANA_PROXY_USERNAME/PASSWORD 的 Basic 认证。
package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

const kibanaInternalBase = "http://nss-kibana:5601"

// 全局代理实例，main 启动时通过 newKibanaProxy 初始化
var kibanaProxy = &kibanaReverseProxy{}

type kibanaReverseProxy struct {
	auth string // Basic 认证头值
}

// newKibanaProxy 从环境变量读取 Kibana 代理账号
func newKibanaProxy() (*kibanaReverseProxy, error) {
	user := os.Getenv("KIBANA_PROXY_USERNAME")
	pass := os.Getenv("KIBANA_PROXY_PASSWORD")
	if user == "" || pass == "" {
		return nil, fmt.Errorf("KIBANA_PROXY_USERNAME/PASSWORD 未配置")
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	return &kibanaReverseProxy{auth: auth}, nil
}

// ServeHTTP 反向代理 /kibana/* 到 Kibana（保留 /kibana basePath 前缀）
func (p *kibanaReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		req.Header.Set("Authorization", p.auth)
		req.Header.Set("kbn-xsrf", "true")
	}
	proxy.ServeHTTP(w, r)
}
