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

// reloadSuricata 通过 unix socket 触发规则热加载（suricata 未启动时仅告警）
func reloadSuricata() error {
	if _, err := os.Stat(socketPath); err != nil {
		return fmt.Errorf("suricata socket 不可用: %v", err)
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	msg := map[string]any{
		"version": "0.1",
		"id":      fmt.Sprintf("ndr-manager-%d", time.Now().UnixNano()),
		"method":  "reload-rules",
	}
	data, _ := json.Marshal(msg)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
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
