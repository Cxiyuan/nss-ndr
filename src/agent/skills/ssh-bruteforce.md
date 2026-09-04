---
name: hunting-ssh-bruteforce
description: SSH (22) 暴力破解 + 认证失败率升高
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-006]
  keyword: [ssh, bruteforce, 22]
context_budget: 1200
mcp_tools: [query_peer_relations, count_behavior_hits, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别针对 22 端口的 SSH 暴力破解,区分正常运维批量登录。

## 分析步骤
1. summary 看 `conn_state` 与失败率;**持续 S0 + 中等速率**比突发高速更具威胁
2. `query_peer_relations`:源平时是否连 22(运维 / 扫描机)
3. `count_behavior_hits`:近 24h 该源是否多次爆破
4. `get_entity_profile`:源是否已知运维机/可疑

## 判定阈值
- 5min 内 ≥ 20 连接且失败率 ≥ 0.7 → **medium**
- 失败率 ≥ 0.9、跨多目标、24h 内重复 → **high**
- 单次/低频,失败率 < 0.4 → low 记录

## 示例
{"risk_level":"medium","verdict":"ssh_bruteforce_suspected","evidence":"5min 内 10.0.0.7 向 3 个 22 目的发起 28 次 SSH 失败率 0.86,源 24h 内首次出现","iocs":[{"type":"ip","value":"10.0.0.7"}],"suggest_action":"堡垒机自动封禁源 30min;堡垒机/WAF 同步该 IP;取样抓包留存爆破用户名字典"}
