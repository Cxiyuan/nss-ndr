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
{"risk_level": "high", "verdict": "data_exfiltration_suspected", "evidence": "引用本会话 BEH-xxx/features 的真实字段与数值(命中规则时以 BEH-xxx 窗口统计为第一依据)", "iocs": [], "suggest_action": "按本会话真实情况给出可执行处置(不得照抄示例)"}
