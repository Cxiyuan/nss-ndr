# 智能体任务输入复核 v2(2026-09-05)

> 版本:2.0 · 对应部署:agent sha-10e6997(守卫版)+ logstash-databus sha-1a110e8
> 方法:服务器 Redis 流最新 800-900 条实测 + 原始 zeek 日志列覆盖统计 + worker 语义本地复现
> (stream→EventEnvelope→session_key 分组→RuleEngine.build_unit→task_json 预览)

## 结论摘要
输入链路结构完好(envelope + zeek 透传 + summary.features + behavior_hits),但**现网流量下的实际输入存在 7 个问题**,
其中 2 个高价值(dhcp 垃圾会话、weird 高价值信号浪费),1 个字段错配(ssh attempts)。

## 1. 实测数据构成(最新 800 条)
- dataset:zeek.connection 366 / zeek.dhcp 133 / zeek.weird 114 / zeek.dns 98 / zeek.ssl 70 / zeek.ssh 13 / zeek.ntp 6
- 带 zeek 透传 547/800(68%);proto 空 336(42%);空 src/dst 133(全为 zeek.dhcp)
- ts = logstash 到达时间(非 zeek 事件时间),事件真实时间只在 zeek 载荷/ES 侧

## 2. 问题清单

### P1-A:zeek.dhcp 五元组全空 → 全部坍缩进 `sess:::udp` 垃圾会话
- dhcp.log 无 id.*(DHCP 无 L3 元组),logstash `event.get("id.orig_h")` → "";133 条中 80 条 src/dst/port 全空
- worker 按 (src,dst,port,proto) 分组 → 所有 DHCP 事件同 key → 单批 62+ 条堆一个会话,
  task_json:`{"session_key":"sess:::udp","datasets":{"zeek.dhcp":62},"dst_ports":[],"features":{}}`
- 后果:每批白耗 1 次模型调用、判定文档被 sess::: 污染、无任何信号
- 且 SIGNAL_FIELDS 无 zeek.dhcp(host_name/client_addr/assigned_addr/mac/msg_type 全丢)

### P1-B:zeek.weird(现流量 14%)有高价值字段但零透传零特征
- weird.log 字段 name/notice/source 齐备(如 possible_*/TCP_ack_underflow 等异常类型),SIGNAL_FIELDS 无 zeek.weird
- weird 会话 task_json 只有五元组+datasets 计数,模型盲判;weird 在 zeek 里本就是"协议异常"信号

### P2-A:ssh 透传字段名错配
- SIGNAL_FIELDS 配 `attempts`,实际 zeek 字段是 `auth_attempts`(544 行有、attempts 0 行)→ SSH 尝试数丢失
- auth_success 0 行(流量未见连接结束行,先记录)

### P2-B:proto 空 → 同流跨会话拆分
- ssh/weird 无 proto 字段(留空)→ 会话键 proto 为 "*",与同流 conn 的 "...:22:tcp" 拆成两个会话
  (实测 172.16.199.235→172.16.196.79:22 同时存在 `:22:tcp`(conn 17)与 `:22:*`(weird44+ssh14))
- 影响:BEH-006(SSH 爆破,session scope,只吃 zeek.connection 的 tcp 会话)看不到 ssh.log 侧;规则/特征按流碎片化

### P2-C:上游字段覆盖率低(非 agent 可改,需上游/流量侧确认)
实测列覆盖率(zeek 8.2.2 + databus local.zeek,卷 /var/lib/docker/volumes/nss-ndr-zeek-logs/_data):
| 日志 | 字段 | 覆盖率 | 影响 |
|---|---|---|---|
| conn.log | conn_state/history/pkts | ~100% | ✓ |
| conn.log | service | 6065/14388(42%) | services_dist 稀疏 |
| conn.log | duration/orig_bytes/resp_bytes | 8310/14388(58%) | bytes_sum/duration_sum 半盲 |
| http.log | status_code/request_body_len | 73/73 | ✓ |
| http.log | method/host/uri/user_agent | **0/73** | BEH-003/008/010(method/uri 规则)与 top_uris/hosts 全失效 |
| dns.log | query/rcode/answers | ~100% | ✓ |
| dns.log | qtype_name | 96/3791(2.5%) | qtype_dist 空 → TXT 隧道特征盲区 |
| ssl.log | version/cipher | 2389/2389 | ✓ |
| ssl.log | server_name/ja3/subject | **0/2389** | sni_set/ja3_cnt 恒空;ssl 技能/锚点失效 |
| ssh.log | auth_attempts/client | 544/544 | 字段名错配见 P2-A |
- ssl/http 缺字段定性:全部 ssl 行 `established:false, resumed:false, ssl_history:"si"`
  = 只见服务端方向(未见 ClientHello)→ SNI/JA3/method/uri 结构性不可见(流量侧特性,非配置错误);
  dns qtype_name 缺失原因未明(留待上游查,query 本身可见)

### P3:会话语义 = "5s 批内同四元组片段"
- 无跨批会话累积(除 D1 规则窗口),长连接被按批切成多个 event_count 1-N 的小会话;
  model 需 es_search 自行跨会话关联(D2 日志已证实命中场景走该路径)

## 3. 修复状态(commit 057a668,已上线验证 2026-09-05)
1. **P1-A 已修**:logstash 对 zeek.dhcp 不再 XADD(unless dataset=="zeek.dhcp")。
   验证:最新 150 条流 dhcp 仅剩重启残留 1 条,后续写入为 0;sess::: 判定 8 分钟 0 例 ✓
2. **P1-B 已修**:SIGNAL_FIELDS 补 zeek.weird[name notice source];engine 新增
   _summarize_weird(names/notice_count);task/system 特征表与 evidence_guard 键词表同步。
   验证:流内 weird zeek 载荷 = {"name":"active_connection_reuse","notice":false,"source":"TCP"} ✓
3. **P2-A 已修**:ssh SIGNAL_FIELDS attempts → auth_attempts(zeek 实际字段名)✓
4. **P2-B 已修(commit f915e6b,输入重心轮)**:app/pipeline/grouping.py 批内 proto 回填
   (conn 行优先,同 (src,dst,dst_port) 兄弟事件回填 ssh/weird 空 proto)+ group_by_session;
   worker.run_once 接入。真实数据回放:SSH 流 ':22:*'(58)+':22:tcp'(17)→ 单 ':22:tcp'(75,
   weird44+ssh14+conn17);443 流同效。线上验证:重启后 ':22:*' 碎片判定 0 例。
   同时新增 zeek.ssh 特征汇总(attempts_sum/auth_success_cnt/clients),task/system 特征表
   与 evidence_guard 键词表同步。
5. **P3 已修(commit 80053ca,输入重心轮)**:EpisodeAccumulator 跨批累积同
   (src,dst,dst_port) 事件为情节(空闲 12s/事件 200/存活 300s/情节数 300 任一即 flush),
   worker.run_once 改造(先累积后整段判定,flush 前不 ack/不打 evt 标记,崩溃由
   XAUTOCLAIM 重投重建);flush 时 proto 回填 + session_key 分组。真实流模拟:500 事件
   → 154 情节(dns-53 流 56 事件整段);线上验证:判定文档 event_count 出现 10-20 的
   整段情节(此前被切成 2-4 个批内片段),PEL/DLQ 正常。测试 +5,全量 63 过。
6. P2-C(上游列覆盖:ssl SNI/JA3、http method/uri、dns qtype_name):记录待上游/流量侧确认
7. DHCP 富化(当前跳过)与 rdp/kerberos/smb_cmd/ntlm summarize:可选后续项

## 3b. 修复后的输出侧观察(重要)
输入修复后 agent(守卫版)在低信号流量上 evidence 高频以"引用本会话 features.zeek.dns 的
avg_entropy 值与窗口统计"开头(0.6B 照抄 sanitized 示例开头词)→ 守卫全部拦截降级 uncertain,
近期判定 ~100% uncertain(安全但无区分度)。结论:输入侧问题已清,输出侧 0.6B 的
grounded-evidence 生成需换强模型(cloud 升级路径已就绪)或结构化 evidence schema 改造,
属下一阶段课题,与守卫"绝不编造"方针一致。
4. **(记录,不修)ssl/http 方向性缺字段、dns qtype_name** —— 上游/流量特性,现有 es_search 兜底
5. **(记录)proto 空拆分** —— 可接受;后续可在 logstash 侧用同 uid 的 conn 事件回填 proto

## 4. 验证材料
- 复现脚本 /tmp(流 dump + 本地 task_json 重建)已在本轮使用;上文 task_json 预览为真实会话重建
