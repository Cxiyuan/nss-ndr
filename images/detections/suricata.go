package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const socketPath = "/var/run/suricata/suricata-command.socket"

// reloadSuricata 通过 suricata unix socket 触发规则热加载
func reloadSuricata() error {
	if _, err := os.Stat(socketPath); err != nil {
		// socket 不可用时仅告警（如 suricata 未启动），不阻断规则写入
		fmt.Printf("warn: suricata socket 不可用: %v\n", err)
		return nil
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("连接 suricata socket 失败: %w", err)
	}
	defer conn.Close()

	msg := map[string]any{
		"version": "0.1",
		"id":      fmt.Sprintf("detections-%d", time.Now().UnixNano()),
		"method":  "reload-rules",
	}
	data, _ := json.Marshal(msg)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("发送 reload-rules 失败: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("读取 suricata 响应失败: %w", err)
	}
	var resp struct {
		Return string `json:"return"`
	}
	_ = json.Unmarshal([]byte(line), &resp)
	if resp.Return != "OK" {
		return fmt.Errorf("suricata reload 未确认: %s", strings.TrimSpace(line))
	}
	return nil
}
