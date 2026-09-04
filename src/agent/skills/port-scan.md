---
name: hunting-port-scan
description: 端口/服务扫描(同一源 IP 短时连接大量 dst_ip:port)
version: 1.0
triggers:
  proto: [tcp, udp, icmp]
  behavior: [BEH-005]
  keyword: [scan, recon, sweep]
context_budget: 1000
mcp_tools: [query_peer_relations, es_search]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别扫描器对内网网段或对外资产的系统性探测。
## 步骤
1. summary 唯一 dst_port 数 / 唯一 dst_ip 数 / 速率(conn/s)
2. `query_peer_relations`:源平时是否对网段外 / 是否常见扫描源(Zgrab/Masscan 等 user_agent 在 http 日志里更明显)
3. `es_search` 1h 内同源命中其他 BEH 的频次
## 判定
- 唯一端口 ≤ 5 → low
- 唯一端口 6-50 或 持续 ≥ 5min → medium
- 唯一端口 > 50 或 持续 ≥ 30min 或 含敏感端口(22/3389/445/3306/1433) → high
## 示例
{"risk_level":"medium","verdict":"port_scan_suspected","evidence":"10.0.0.7 在 3min 内对 10.0.0.0/24 发起 142 次连接,涉及 18 个目的 67 个端口,含 22/445/3389/3306","iocs":[{"type":"ip","value":"10.0.0.7"}],"suggest_action":"边界 ACL 封禁源 10.0.0.7 24h;调取源主机最近 24h 登录与进程行为(是否已被控)"}
