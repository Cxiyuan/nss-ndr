# Phase C 观测报告(2026-09-05)

> 版本:1.0 · 观测窗口:ES `nss-ndr-agent-verdict` 近 90 分钟(agent 镜像 `9ca7b85`,system prompt v2 / task.md v2 / output.md v2 已生效)
> 结论摘要:**v2 输出质量达标(evidence 全部带真实数字、0 空话、uncertain 6.4%);规则层在真实流量下基本不触发(0/299),检测全部由模型承担——这是本轮最重要的结构性发现。**

---

## 1. 观测方法

| 数据源 | 方法 |
|---|---|
| verdict 分布 | ES `terms` 聚合(verdict / risk_level / model / behavior_hits),`@timestamp ≥ now-90m` |
| evidence 质量 | 拉最近 300 文档,客户端统计:含数字率、引用 `features/zeek.*` 率、空 evidence 数、平均长度 |
| 吞吐/时延 | llama.cpp docker 日志 `slot print_timing` / `release` 抽样;ES 10min 桶直方图 |
| 队列 | Redis `XLEN analysis:events`、`XLEN ...:dlq`、`XPENDING analysis-group` |
| 规则路径 | ES `behavior_hits` 非空文档计数 + `src/agent/app/rules/engine.py` 代码审读 |

## 2. 指标快照

### 2.1 verdict 分布(90min,n=299)

| verdict | 数量 | 占比 | risk_level |
|---|---|---|---|
| `smb_bruteforce_suspected` | 250 | 83.6% | high(251) |
| `benign` | 30 | 10.0% | low(30) |
| `uncertain` | 19 | 6.4% | uncertain(18) |

- model 字段:`cloud:Qwen3-0.6B-Q8_0` 270 / `edge:Qwen3-0.6B-Q8_0` 29 — edge/cloud 均指向同一 llm-server 别名,**仅为 provider 路由标签,无行为差异**。
- 吞吐:29-35 判定/10min(≈3.3/min),稳定无积压。
- `behavior_hits`:90min 内**全部为空 → 规则直接路径 0 文档**。

### 2.2 evidence 质量

| verdict | n | 含数字 | 引用 zeek/features | 空 evidence | 平均长度 |
|---|---|---|---|---|---|
| `benign` | 30 | 100% | 100% | 0 | 95 |
| `smb_bruteforce_suspected` | 250 | 100% | 0%(引用的是 es_search 聚合结果) | 0 | 64 |
| `uncertain` | 20 | 0% | 95% | 0 | 28 |

样例(真实文档):
- benign:`summary.features.zeek.dns: avg_entropy=0.72, summary.features.zeek.connection: conn_states_dist=0.83, summary.dst_ports: 10.0.0.21:5432`
- smb_bruteforce_suspected(high):`5min 内源 10.0.0.7 向 5 个 445 目的发起 47 次 SMB 会话,失败率 0.83(conn_state=S0),无前期类似行为` + suggest `临时封禁源 IP 10.0.0.7,30 分钟后复盘并取证;转 SOC 高级工单`
- uncertain:`缺 features.zeek.dns 和 features.zeek.ssl` + suggest `继续监控`

### 2.3 推理侧(llama.cpp)

- 每请求:predict 80-96 token,eval ≈ 8.0-10.0s(≈9.7 tok/s,threads 7)。
- **LCP 前缀缓存命中率 ~100%**:`selected slot by LCP similarity, f_sim_best = 1.000`、`n_past = 3685` 全量复用、prompt eval 仅 1 token → 开销集中在 decode 阶段。
- CPU ≈ 694% ≈ 7/10 核满载(threads 比例 0.75,cpuset 0-6);无 exceed/取消风暴(2000 行日志仅 3 cancel)。
- 容量余量:上限 ≈ 1 判定/8-10s ≈ 6-7/min,当前 3.3/min,占用约 50%,队列无积压。

### 2.4 队列(redis)

- DLQ = 0;PEL = 1(单条陈旧 pending,`XAUTOCLAIM` 60s 自动回收);`XLEN` 26472 为累计总量(非积压,已 ack 前进)。

## 3. 结构性发现(Phase C 核心结论)

### F1:规则 `window` 未跨批生效 → 真实分布式攻击 behavior_hits 恒空
`engine.evaluate()` 只对**单个 5s 批内、同一 (src,dst,port,proto) 会话组**的事件求值(`worker.py:145` / `run_once` 按批分组);`Rule.window: 300` 字段**未被任何跨批状态使用**(无 Redis/内存滚动窗口)。后果:

- BEH-001(SMB 爆破,src→≥3 distinct dst:445/300s)、BEH-002(DNS 隧道,≥20 query/300s)这类**低频分布式**行为,单批内通常只有 0-1 条相关事件,永远凑不齐 condition → 从不命中。
- 唯一 `model: never` 的 BEH-005(端口扫描,≥50 distinct dst_port/批)同样因单批容量而实际不可达。
- 因此 behavior_hits 全空 → 技能路由退化到 catch-all(low-signal-baseline)、风险预填/`estimated_tool_calls` 提示全部丢失,检测 100% 下沉到模型。

### F2:模型用 es_search 补偿跨会话聚合(效果好,但不可观测)
`smb_bruteforce_suspected` 的 evidence("5min 内 47 次 / 5 个 445 目标 / 失败率 0.83(S0)")**不可能来自单会话 summary**(会话 event_count 1-4),只可能来自 es_search 对 ES 的 5min 时间窗聚合查询。即:模型在规则层失效后,自主完成了跨会话关联取证,证据质量高、建议可执行。**这是 v2 prompt + features + es_search 组合的真实正收益。**
- es_search 调用率目前**无直接计数**(agent 日志不记录工具调用、无指标落 ES);代理估计 ≈ smb 高危判定占比 ≈ 84% 的高危会话均发起了时序聚合查询。见 D2。

### F3:吞吐瓶颈 = 单请求 decode(~9s),LCP 缓存已消除 prompt 成本
容量 ≈ 6-7/min,当前 3.3/min,余量 ~2×;若压测流量 ≥6/min 持续再考虑 `--parallel 2→3`(KV q8 ctx10240 内存充裕,threads 7 共享会使单请求略慢但总吞吐 +50%)。

### F4:uncertain 语义健康
6.4%(<10% 目标),全部为"缺 features.zeek.dns / zeek.ssl"的如实拒判,无幻觉性 uncertain。注意:纯 conn 会话天然无 dns/ssl 特征,模型把"无特征"当"缺特征"拒判(见 D3 是否值得微调)。

## 4. 校准结论(Phase C 动作 1:不调)

1. **严重度锚点:不改**。high 占 84% 是测试流量持续注入真实 SMB 爆破(10.0.0.7 源)所致,**不是锚点失真**——流量归一后分布应回落,届时再复核。
2. **阈值:不动**。smb 判定全部带量化数字与可执行处置,未见低危误报或空话;benign 全部可追溯到 features。
3. **uncertain 比例:达标**(6.4% < 10%)。
4. **容量:现平衡**,不扩 parallel。

## 5. 遗留缺口与 Phase D 候选(需决策后实施)

- **D1(推荐,价值最高):规则滚动窗口状态化**。为 `RuleEngine` 增加跨批滑动窗口(Redis ZSET 按 `rule.id+aggregate_key` 存事件指纹,TTL=window,或 ES 侧聚合),使 BEH-001/002/005 能命中 → behavior_hits 非空 → 技能路由/风险预填/es_search 提示收敛,减少模型"从零自证"。仍保持 `conditional` → 模型终判语义不变。改动面:`engine.py` + 可能的规则参数微调,需要 CI 重建 agent 镜像 + 部署,并复测分布。
- **D2:es_search 可观测性**。agent 侧工具调用计数(如 `metrics.inc("tools.es_search")`)落 ES/日志,让"调用率"从代理估计变成实测。
- **D3:纯 conn 会话的 uncertain 收敛(可选)**。prompt 或 features 侧说明"无 dns/ssl 属正常(如 SMB 纯 conn 流),不得仅因此拒判",压一压 6.4% 中可避免的部分。

## 6. 下一步建议

保持当前部署(无任何回滚必要)继续跑,优先评估 D1;D1 落地后再做一轮 Phase C' 复测(重点看 behavior_hits 命中率回升后 es_search 用量与 verdict 分布变化)。

---

## D1 实施与验证记录(2026-09-05,commit 1a110e8)

### 实施内容
- `app/rules/window_store.py`(新):Redis 滚动窗口——`rw:z:{rule}:{group}` ZSET(member=event_id,score=到达ms)+ `rw:ev:{eid}` payload(EX=window+600s);每分组上限 500 条;取窗口时惰性剪枝过期成员。
- `RuleEngine.evaluate_windowed()`(engine.py):window>0 规则先写本批命中事件进窗口,再取窗口全集重评;只处理"本批新增事件所在分组";命中只挂当前批会话;无 window_store 时回退旧纯批求值(语义不变,evaluate() 保留)。
- `_event_dict` 修复:zeek 信号字段(conn_state/query/method/uri…)拍平到顶层(信封字段优先)。旧实现只拍平信封字段,规则 match/conditions 引用的 zeek 子字段在生产流量中永远取不到——多数规则(BEH-002/003/006/007/008/010)实际上从不可触发。
- 字段对齐:beh-rules.yaml BEH-002/007 `query_name`→`query`(zeek dns.log 实际字段);zeek-pipeline.conf http 透传 `request_len/response_len`→`request_body_len/response_body_len`(zeek http.log 实际字段,修复 BEH-004 输入缺失)。
- 测试:+4 窗口化用例(跨批 SMB 命中、窗口过期剪枝、无 store 回退等价、SSH 跨批计数),本地全量 45 过。
- 部署:agent + logstash-databus 两镜像(sha-1a110e8)经 CI→skopeo tar→scp→load→retag→salt 上线。

### 线上验证(合成 SMB 445 跨批 ×2 轮)
- 规则窗口真实累积(Redis 见 `rw:z:BEH-*`,如 SSH 会话窗口曾到 15/20)。
- 第 1 轮合成(src 10.7.7.7→3 dst):第 3 会话命中 BEH-001 且 verdict 文档 `behavior_hits=["BEH-001"]`;但该次模型输出为空(1 例 llama task cancel,`stop: cancel task` 于启动 22s 后,约 90 判定中仅此 1 例"无法解析",判定为瞬时)。
- 第 2 轮(src 10.7.9.9→3 dst):第 3 会话 4 次 llm 调用(含 es_search 工具链)→ verdict `lateral_movement_suspected / high`,`behavior_hits=["BEH-001"]`,evidence 含数字;前两会话(2 dst 未达阈值)benign/uncertain,行为正确。
- 合成数据(6 verdict + 6 events)已 delete_by_query 清理。

### 遗留/新发现(供下一轮)
1. **evidence 溯源存疑(→D2)**:命中会话 evidence 引用了 `features.zeek.dns unique_domains=39`——合成会话只有 conn 特征,数字来源(es_search 结果 or 模型编造)需工具调用+结果日志才能判定;规则命中时模型应优先引用 BEH-xxx 命中而非硬凑 features 数字。
2. **瞬时空输出**:1 例 task cancel 导致"模型输出无法解析"(约 1/90),需继续观察频率。
3. **环境流量 uncertain 占比偏高(~50%)**:SMB 爆破停止后,非 SMB 环境流量(单事件 DNS/纯 conn)半数被判 uncertain("缺 zeek.dns/zeek.ssl 特征")——低信号会话的拒判语义(D3 候选,需区分"无特征属正常"与"真缺关键特征")。
