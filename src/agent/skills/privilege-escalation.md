---
name: hunting-privilege-escalation
description: 权限提升——异常进程行为(sudo / setuid / SUID / capabilities 滥用)
version: 1.0
triggers:
  proto: []
  behavior: [BEH-011]
  keyword: [privesc, sudo, setuid, suid]
context_budget: 1200
mcp_tools: [query_peer_relations, es_search, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别可疑的本地提权尝试:日志中 sudo -l、SUID 探测、kernel exploit、容器逃逸。
## 步骤
1. summary 看 `notice.msg`/`notice.sub` 是否含 ProcessOutOfBoundsAccess、SUIDProbe、SetuidOperation、ContainerEscape
2. `es_search` 1h 内同源主机相关可疑进程/告警
3. `get_entity_profile` 源主机角色
## 判定
- 单次 SUID 探测(脚本类) → low 记录
- 多次提权 / 容器逃逸 / 内核 OOB 访问 → high
- 与凭据窃取或横向移动叠加 → 升级 high
## 示例
{"risk_level":"high","verdict":"privilege_escalation_suspected","evidence":"主机 10.0.0.5 zeek.notice 在 2min 内触发 5 次 ContainerEscape(Linux capabilities 探测),1 次 SUIDProbe(/usr/bin/su)","iocs":[{"type":"ip","value":"10.0.0.5"}],"suggest_action":"立即冻结该主机容器/进程取证;审计最近 24h sudo/auth.log;横向排查是否已获 root"}
