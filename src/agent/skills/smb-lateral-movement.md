---
name: hunting-smb-lateral-movement
description: 内网横向移动——SMB (445) 爆破 / 共享枚举
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-001]
  keyword: [smb, lateral, 445]
context_budget: 1400
mcp_tools: [query_peer_relations, count_behavior_hits, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别内网主机对多个目标的 445 端口高频失败连接,判断是 SMB 爆破、共享枚举,还是正常运维。

## 分析步骤
1. summary 必查:`conn_state` 分布(S0 = 失败)、`orig_bytes`/`resp_bytes`、是否多 dst_ip
2. 调 `query_peer_relations` 看源 IP 平时对 445 的对端面,**是否首次**、是否集中在新网段
3. 调 `count_behavior_hits` 看近 24h 该源是否还有其他爆破行为
4. 调 `get_entity_profile` 判断源是否已知运维/扫描机/被控主机

## 判定阈值
- 唯一 dst_ip ≥ 3 且失败率 ≥ 0.7 → **medium**
- 唯一 dst_ip ≥ 10 或失败率 ≥ 0.9 或跨 2 个 + B 段 → **high**
- 单次/极少数目的、失败率 < 0.4 → low 记录

## 示例
{"risk_level": "medium", "verdict": "smb_bruteforce_suspected", "evidence": "引用本会话 BEH-xxx/features 的真实字段与数值(命中规则时以 BEH-xxx 窗口统计为第一依据)", "iocs": [], "suggest_action": "按本会话真实情况给出可执行处置(不得照抄示例)"}
