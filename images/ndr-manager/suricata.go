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

// suricataCommand 通过 unix socket 向运行中 suricata 发送命令（Suricata 8 命令 socket 0.2 协议）
// 协议：先握手 {"version":"0.2"}，再发送 {"command":"<method>"}，响应为带 \n 的 JSON
func suricataCommand(method string) (map[string]any, error) {
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("suricata socket 不可用: %v", err)
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	// 0.2 协议握手
	if _, err := conn.Write([]byte(`{"version":"0.2"}` + "\n")); err != nil {
		return nil, err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, fmt.Errorf("suricata 握手失败: %v", err)
	}
	// 发送命令（0.2 协议用 command 键，非 0.1 的 method）
	data, _ := json.Marshal(map[string]any{"command": method})
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var resp struct {
		Return  string            `json:"return"`
		Message json.RawMessage   `json:"message"`
	}
	_ = json.Unmarshal([]byte(line), &resp)
	out := map[string]any{"return": resp.Return}
	if len(resp.Message) > 0 && string(resp.Message) != "null" {
		out["message"] = resp.Message
	}
	if resp.Return != "OK" {
		return out, fmt.Errorf("suricata %s 未确认: %s", method, strings.TrimSpace(line))
	}
	return out, nil
}

// reloadSuricata 通过 unix socket 触发规则热加载（suricata 未启动时仅告警）
func reloadSuricata() error {
	_, err := suricataCommand("reload-rules")
	return err
}

// suricataStats 查询规则统计与最近重载时间（对齐 SO so-suricata-rulestats）
func suricataStats() (map[string]any, error) {
	stats, err := suricataCommand("ruleset-stats")
	if err != nil {
		return nil, err
	}
	reload, rerr := suricataCommand("ruleset-reload-time")
	if rerr != nil && reload == nil {
		return nil, rerr
	}
	parse := func(m map[string]any) []map[string]any {
		raw, _ := json.Marshal(m["message"])
		var out []map[string]any
		_ = json.Unmarshal(raw, &out)
		return out
	}
	sm := parse(stats)
	rm := parse(reload)
	out := map[string]any{"return": stats["return"]}
	if len(sm) > 0 {
		out["rules_loaded"] = sm[0]["rules_loaded"]
		out["rules_failed"] = sm[0]["rules_failed"]
	}
	if len(rm) > 0 {
		out["last_reload"] = rm[0]["last_reload"]
	}
	return out, nil
}
