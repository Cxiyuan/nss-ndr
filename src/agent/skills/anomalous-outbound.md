---
name: hunting-anomalous-outbound
description: 异常出向回连(非合作方 IP / 长连接 / 反向 shell 特征)
version: 1.0
triggers:
  proto: [tcp, udp]
  behavior: [BEH-009]
  keyword: [anomalous_outbound, beacon, c2, reverse_shell]
context_budget: 1400
mcp_tools: [query_peer_relations, es_search, detect_chain_sequence]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别内网主机向罕见 / 已知 C2 / 异常端口 / 长连接 出向回连。
## 步骤
1. summary `duration` 高 / `conn_state=SF` / `orig_bytes` 小 `resp_bytes` 大(交互式);或 notice `SubType=Outbound::KnownC2`
2. `query_peer_relations`:dst_ip 是否合作方 / 首次出现
3. `es_search` 1h 内同源其他异常出向
4. `detect_chain_sequence` 多源同目的 → 可能是 C2 集群
## 判定
- 偶发长连接到已知合作方 → low
- 罕见目的 / 长连接 / 定期往返(beacon)→ medium
- 已知 C2 指标 / 反向 shell 特征 / 加密 + 高字节交互 → high
## 示例
{"risk_level":"high","verdict":"anomalous_outbound_suspected","evidence":"源 10.0.0.5 对 185.220.101.7:443 持续 3h 单连接交互式流量 orig 12KB resp 380KB,与已知 Tor 出口列表命中","iocs":[{"type":"ip","value":"10.0.0.5"},{"type":"ip","value":"185.220.101.7"}],"suggest_action":"立即隔离源主机取证;ACL 封禁目的 IP;转云端威胁情报;取样 pcap 留存反向 shell 行为"}
