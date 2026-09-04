---
name: hunting-dns-tunneling
description: DNS 隧道 / C2 心跳 (长域名 / 高熵 TXT / 异常 A 记录)
version: 1.0
triggers:
  proto: [dns, udp]
  behavior: [BEH-002, BEH-007]
  keyword: [dns_tunnel, beacon, high_entropy, txt_query]
context_budget: 1600
mcp_tools: [query_peer_relations, es_search, detect_chain_sequence, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别通过 DNS 外传数据或建立 C2 心跳的隧道,区分正常递归查询。
## 步骤
1. 查 `query_name` 熵 / 标签长度 / QTYPE(TXT 占比) / 唯一域数
2. `es_search` 1h 内同源 DNS 频次与唯一域数
3. `query_peer_relations` 该源的对端面(是否首次 / 罕见 resolver)
4. `detect_chain_sequence` 多 IP 共同访问同组域 → 可能 C2 集群
5. `get_entity_profile` 源是否已知 DNS 出口 / 服务器
## 判定
- 熵 > 3.5 且标签 > 40 且 1h 唯一域 > 50 → **high**
- 高频 TXT + 罕见 TLD → medium
- 偶发长名,无其它异常 → low 记录
## 示例
{"risk_level":"high","verdict":"dns_tunnel_suspected","evidence":"5min 内 10.0.0.5 发起 87 次 DNS 查询 query_name 平均熵 4.1 长度 58 TXT 78% 异常分 0.82;近 24h 已有 3 次同类会话","iocs":[{"type":"ip","value":"10.0.0.5"}],"suggest_action":"内部 DNS 阻断源 53/tcp+udp 出向 10min;抓包留存并转云端复核"}
