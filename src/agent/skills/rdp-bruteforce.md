---
name: hunting-rdp-bruteforce
description: RDP (3389) 暴力破解
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-012]
  keyword: [rdp, bruteforce, 3389]
context_budget: 1200
mcp_tools: [query_peer_relations, count_behavior_hits]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
针对 3389 端口的高频失败 RDP 会话,判断是否为爆破。
## 步骤
1. summary 失败率(失败 conn 数 / 总 conn 数)
2. `query_peer_relations`:源 IP 平时对 3389 的对端面、是否集中针对堡垒机
3. `count_behavior_hits`:近 24h 源 IP 是否多次触发 RDP/SSH 爆破
## 判定
- 失败率 ≥ 0.7 且 5min 内 ≥ 15 连接 → medium
- 失败率 ≥ 0.9、跨多目标、含 SMB 后续活动 → high
- 偶发单次失败 → low 记录
## 示例
{"risk_level": "medium", "verdict": "rdp_bruteforce_suspected", "evidence": "引用本会话 BEH-xxx/features 的真实字段与数值(命中规则时以 BEH-xxx 窗口统计为第一依据)", "iocs": [], "suggest_action": "按本会话真实情况给出可执行处置(不得照抄示例)"}
