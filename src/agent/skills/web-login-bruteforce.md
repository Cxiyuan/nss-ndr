---
name: hunting-web-login-bruteforce
description: Web 登录接口 (POST) 账号爆破 / 撞库
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-003]
  keyword: [web, bruteforce, login, 401]
context_budget: 1200
mcp_tools: [query_peer_relations, count_behavior_hits]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别对 Web 登录接口的高频失败 POST(401/200 比例异常)。
## 步骤
1. summary `status_code` 比例、`uri` 是否 /login /admin 等
2. `query_peer_relations` 源是否首次访问该 dst
3. `count_behavior_hits` 24h 源是否其他爆破
## 判定
- 401/200 比例 0.5-0.8 且 5min 内 ≥ 10 次 → medium
- 失败率 > 0.9 + 跨多 dst / 长时间 → high
- 偶发失败率 < 0.5 → low
## 示例
{"risk_level":"medium","verdict":"web_login_bruteforce_suspected","evidence":"5min 内源 10.0.0.7 对 /login 发起 38 次 POST,401 比例 0.71;近 24h 源首次出现","iocs":[{"type":"ip","value":"10.0.0.7"},{"type":"url","value":"https://10.0.0.21/login"}],"suggest_action":"WAF/登录限流 + 账号锁定策略;复盘是否已有账号被攻破;同步威胁情报"}
