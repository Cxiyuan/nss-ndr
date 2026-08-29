---
name: ssh-bruteforce-hunting
description: 检测 SSH 暴力破解（认证失败率升高 + 连接风暴）
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-006]
context_budget: 1000
mcp_tools: [query_peer_relations, count_behavior_hits, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs]
---
## 目标
识别针对 22 端口的 SSH 暴力破解，区分正常运维批量登录。

## 分析步骤
1. 确认会话聚合计数与失败率（conn_state 分布）。
2. 调用 count_behavior_hits 查看该源 IP 历史命中次数。
3. 调用 get_entity_profile 获取实体画像，判断是否为已知运维主机。
4. 输出 JSON 结论；iocs 填源 IP。

## 判定阈值（参考）
- 5 分钟内连接数 ≥ 20 且失败率 ≥ 0.7 → Medium
- 历史多次命中且扩散到多目标 → High（升级云端复核）
