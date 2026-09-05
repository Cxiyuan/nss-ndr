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

## 3. 建议修复(按价值排序,均走 CI→部署)
1. **logstash:DHCP 空五元组处理** —— 不具分析价值的空元组事件不进 analysis:events
   (或透传 dhcp 信号字段 + 伪五元组做"DHCP 服务异常"专门分析;当前建议先跳过,防 sess::: 污染)
2. **logstash:SIGNAL_FIELDS 补 zeek.weird**(name/notice/source)+ engine summarize 加 weird
   (name 集合/notice 标记)→ 模型能看见具体异常类型
3. **logstash:ssh 字段 attempts → auth_attempts**
4. **(记录,不修)ssl/http 方向性缺字段、dns qtype_name** —— 上游/流量特性,现有 es_search 兜底
5. **(记录)proto 空拆分** —— 可接受;后续可在 logstash 侧用同 uid 的 conn 事件回填 proto

## 4. 验证材料
- 复现脚本 /tmp(流 dump + 本地 task_json 重建)已在本轮使用;上文 task_json 预览为真实会话重建
