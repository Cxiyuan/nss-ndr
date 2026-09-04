---
name: hunting-data-exfiltration
description: 数据外传——大包 / 异常出向目的 / 加密 / 上云
version: 1.0
triggers:
  proto: [tcp, tls]
  behavior: [BEH-004]
  keyword: [exfiltration, upload, egress, large_flow]
context_budget: 1400
mcp_tools: [query_peer_relations, es_search, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别内网主机向罕见目的 / 云 / 异常端口大流量或加密上传。
## 步骤
1. summary 看 `orig_bytes` / `resp_bytes` / `service` / 时长 / 速率(byte/s)
2. `query_peer_relations`:dst_ip 是否已知合作方;是否首次出现
3. `es_search` 1h 内同源其他出向大包会话
4. `get_entity_profile` 源主机是否已知数据/开发/上云服务器
## 判定
- 偶发大包 < 1min → low
- 出向罕见目的 / 持续 ≥ 10min / 加密且体积大 → medium
- 持续 ≥ 30min / 多源同目的 / 已知 C2 / 数据类型敏感 → high
## 示例
{"risk_level":"high","verdict":"data_exfiltration_suspected","evidence":"源 10.0.0.5 持续 42min 向 51.91.211.23:443 上传 2.3GB,TLS 加密、目的 IP 罕见,源主机为研发数据库","iocs":[{"type":"ip","value":"10.0.0.5"},{"type":"ip","value":"51.91.211.23"},{"type":"ja3","value":"<会话 ja3>"}],"suggest_action":"立即 ACL 封禁 10.0.0.5 出向 443;隔离主机镜像取证;转云端威胁情报 + SOC 高优工单"}
