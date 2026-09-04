---
name: assessing-low-signal
description: 无规则命中时的低信号单元——首次出现 / 异常但低置信(用于避免误报与 uniform uncertain/low)
version: 1.0
triggers:
  proto: []
  behavior: []
  require_behavior: false  # 故意走 protocol-only 路径:无 BEH 命中 + 任意协议都进 baseline 兜底
  keyword: [low_signal, first_seen, baseline]
context_budget: 800
mcp_tools: [query_peer_relations, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
对**没有命中任何 BEH 规则**的 AnalysisUnit 做兜底:不要无脑输出"uncertain/low"。
需要查 资产是否首次出现、与已知基线是否一致、是否落在白名单段。
## 步骤
1. `get_entity_profile`:`src_ip` 与 `dst_ip` 是否首次出现、资产角色
2. `query_peer_relations`:源平时对 dst 的对端面
## 判定
- 双向都为已知资产 + 业务端口 → benign
- 任一 IP 首次出现 / 端口罕见 / 协议异常 → low 记录(给资产档案积累,不再 uncertain)
## 示例
{"risk_level":"low","verdict":"benign","evidence":"10.0.0.5 首次访问 10.0.0.21:5432,源为研发,目的为 Postgres;1 次握手无异常","iocs":[],"suggest_action":"已纳入资产档案;无"}
