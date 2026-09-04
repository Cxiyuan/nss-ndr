---
name: hunting-credential-theft
description: 凭据窃取——关键文件访问(/etc/passwd, /etc/shadow, NTDS.dit, SAM hive, kube secrets, 凭据文件 HTTP 出向)
version: 1.0
triggers:
  proto: [tcp]
  behavior: [BEH-010]
  keyword: [credential_theft, files, secrets, lfi]
context_budget: 1300
mcp_tools: [es_search, get_entity_profile]
outputs: [risk_level, verdict, evidence, iocs, suggest_action]
---
## 目标
识别对关键敏感文件的访问 / 读取 / 复制 / 出向传输,典型为 LFI 读取、文件落地/上传、Secret 抓取。
## 步骤
1. summary 看 `dataset=zeek.files` 中 filename(是否 /etc/passwd、/etc/shadow、NTDS.dit、id_rsa、kube-secrets、.env、.npmrc)或 `dataset=zeek.http` 中 uri 模式(../../etc/passwd、/proc/self/environ、wp-config.php 等)
2. `es_search` 同源近 1h 是否多次同路径访问
3. `get_entity_profile` 源主机是否高价值(域控、git、k8s master)
## 判定
- 单次 / 已知应用(备份)读取 → low
- 多次 LFI 读取敏感文件 / 大量 .ssh / kube secret 抓取 → high
- 出向传输到罕见目的 → 至少 medium,叠加后 high
## 示例
{"risk_level":"high","verdict":"credential_theft_suspected","evidence":"源 10.0.0.5 触发 17 次 zeek.files 命中 /etc/passwd、/etc/shadow、/root/.ssh/id_rsa;源主机为 git 服务器","iocs":[{"type":"ip","value":"10.0.0.5"},{"type":"filepath","value":"/etc/shadow"}],"suggest_action":"立即断网取证源主机;轮换所有 git/k8s 凭据;检查 /var/log/auth.log 与 auditd 排查横向"}
