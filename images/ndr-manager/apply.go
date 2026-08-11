// k8s 配置下发：更新 nss-ndr-config ConfigMap + 对受影响 workload 滚动重启
// 使用 in-cluster ServiceAccount（轻量 REST 客户端，无 client-go 依赖）
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	configMapName = "nss-ndr-config"
	namespace     = "nss-ndr"
	saTokenPath   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath      = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

var k8sClient *k8sRESTClient

type k8sRESTClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func init() {
	k8sClient = newK8sClient()
}

func newK8sClient() *k8sRESTClient {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil // 本地调试模式：无 k8s 环境，下发跳过
	}
	token, _ := os.ReadFile(saTokenPath)
	ca, _ := os.ReadFile(saCAPath)
	_ = ca
	return &k8sRESTClient{
		baseURL: "https://" + host + ":" + port,
		token:   strings.TrimSpace(string(token)),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: insecureTLS(),
			},
		},
	}
}

func (c *k8sRESTClient) do(method, path string, body any) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("k8s 客户端未初始化（非集群内运行）")
	}
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("k8s API %s %s: %d %s", method, path, resp.StatusCode, string(data))
	}
	return data, nil
}

// applyConfig 渲染配置并下发（更新 ConfigMap -> 滚动重启受影响 workload）
func applyConfig(comment string) error {
	c, err := loadFull()
	if err != nil {
		return err
	}
	rd, err := renderAll(c)
	if err != nil {
		return err
	}
	// 1. 更新 ConfigMap
	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      configMapName,
			"namespace": namespace,
		},
		"data": rd.Data,
	}
	if _, err := k8sClient.do(http.MethodPut,
		fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", namespace, configMapName), cm); err != nil {
		return fmt.Errorf("更新 ConfigMap 失败: %w", err)
	}
	audit("config.apply", configMapName, comment)

	// 2. 滚动重启受影响 workload（DaemonSet 需重建 pod 加载新配置）
	restarted := []string{}
	for _, ds := range []string{"nss-suricata", "nss-zeek", "nss-elastic-agent"} {
		if err := rolloutRestart("daemonsets", ds); err != nil {
			return fmt.Errorf("重启 %s 失败: %w", ds, err)
		}
		restarted = append(restarted, ds)
	}
	for _, dep := range []string{"nss-elasticsearch", "nss-kibana", "nss-xdr-push", "nss-ndr-manager",
		"nss-strelka-frontend", "nss-strelka-backend", "nss-strelka-filestream", "nss-strelka-manager", "nss-strelka-filecheck"} {
		if err := rolloutRestart("deployments", dep); err != nil {
			return fmt.Errorf("重启 %s 失败: %w", dep, err)
		}
		restarted = append(restarted, dep)
	}
	audit("rollout.restart", strings.Join(restarted, ","), comment)
	return nil
}

// rolloutRestart 通过 patch template annotation 触发滚动更新
func rolloutRestart(kind, name string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{
						"ndr-manager/restartedAt": ts,
					},
				},
			},
		},
	}
	data, _ := json.Marshal(patch)
	req, err := http.NewRequest(http.MethodPatch,
		k8sClient.baseURL+fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s", namespace, kind, name),
		bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k8sClient.token)
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err := k8sClient.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", kind, name, resp.StatusCode, string(b))
	}
	return nil
}

// applyRules 更新规则文件（共享 hostPath）+ 触发 suricata 热加载 + 更新 ConfigMap 内规则
func applyRules() error {
	if err := renderRulesFile(); err != nil {
		return err
	}
	if err := reloadSuricata(); err != nil {
		audit("rules.reload", "suricata", err.Error())
	}
	// 同步 ConfigMap 中的 all-rulesets.rules（suricata DS 挂载规则目录为 hostPath，双保险）
	c, err := loadFull()
	if err != nil {
		return err
	}
	rd, err := renderAll(c)
	if err != nil {
		return err
	}
	_ = rd
	return nil
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
