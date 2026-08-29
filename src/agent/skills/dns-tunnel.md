---
name: hunting-for-dns-tunneling-with-zeek
description: 检测 DNS 隧道通信（高熵/长域名/罕见TLD + A记录指向内网IP）
version: 1.0
triggers:
  proto: [dns, udp]
  behavior: [BEH-002, BEH-007]
  keyword: [dns_tunnel, high_entropy_domain, long_label]
context_budget: 1500
mcp_tools: [query_peer_relations, es_search, detect_chain_sequence, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs]
---
## 目标
识别通过 DNS 协议外传数据或建立 C2 心跳的隧道行为，区分正常 DNS 递归查询。

## 分析步骤
1. 从 Zeek DNS 日志提取 query_name，计算熵值与标签长度；记录 QTYPE 分布。
2. 调用 es_search 回溯该源 IP 近 1 小时 DNS 查询频次与域名唯一数。
3. 调用 query_peer_relations 获取对端关系，判断是否为首次异常外联。
4. 若 A/AAAA 记录指向内网 IP 或 TXT 记录含高熵字符串，上调风险。
5. 输出 JSON 结论；iocs 字段填可疑域名与解析 IP。

## 判定阈值（参考）
- 域名熵值 > 3.5 且标签长度 > 40 且 1h 内唯一域名 > 50 → High
- 仅高频 TXT 查询且 QTYPE 异常 → Medium
- 单次长域名、无其它异常 → Low（不告警，仅记录）

## 输出示例
{"risk_level": "High", "verdict": "dns_tunnel_suspected", "evidence": "entropy=4.1 len=58 qtype=TXT->10.0.0.5", "iocs": [{"type": "domain", "value": "xxxx.example.com"}]}
