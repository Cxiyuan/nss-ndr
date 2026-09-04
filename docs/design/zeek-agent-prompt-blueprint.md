# Zeek 日志安全分析 · 专用系统提示词与双侧输入优化蓝图

> **定位**:把智能体从"8 字段信封 + 3 键 summary 的裸判断器"升级为"能看到真实 Zeek 特征、遵守强约束、零幻觉的纯后端安全分析引擎"。
> **本蓝图 = 系统提示词 v2 提案 + 输入侧(logstash/引擎)与智能体侧的配套改造**。
> **前置调研**:`docs/research/agent-input-format.md`;本轮补充确认 logstash 丢弃了除 8 字段外全部 Zeek 详情。
> 版本:1.0(提案态,未落地);落地按本文件第 6 节分阶段执行。

---

## 0. 一句话

> **系统提示词只能约束"模型确实看得到的东西"。** 当前模型看不到任何 Zeek 细节 → 先补输入(让 summary 带真实特征),再写引用这些字段的强约束提示词,否则提示词本身会诱导幻觉。

---

## 1. 输入侧现状(事实,勿凭记忆)

### 1.1 链路与损失点
```
zeek 43 个 dataset 的 JSON 日志(字段齐全)
   ↓ logstash file input (json codec) —— 原始 zeek JSON 全部在事件里
   ↓ ruby filter → Redis XADD —— 只保留 8 字段,其余丢弃 ← 主要损失点
   ↓ EventEnvelope(event_from_stream)—— 再补 2 个元字段
   ↓ RuleEngine.build_unit() —— summary 只算 datasets/dst_ports/behavior_hits
   ↓ AnalysisUnit —— LLM 只能看到上面 3 键 + behavior_hits + watermark
```

### 1.2 实测摘要(本轮)
- `sess:…:53:udp` 70 事件(31 conn + 39 dns),summary 仅 `{datasets:{zeek.connection:31,zeek.dns:39},dst_ports:["53"],behavior_hits:[]}`
- `sess:…:443:tcp` 54 事件(36 conn + 18 ssl)—— SSL 已归入 tcp 会话(上轮修复生效)
- zeek.dhcp 四元组全空 → `sess:*:*:*`(正常)
- **结论:模型对"这 70 个 DNS 事件到底查了什么域"一无所知,除非它主动 es_search**

### 1.3 可用而未用的 Zeek 原始字段(标准 zeek 字段名,logstash 读得到)
| dataset | 高信号字段(原始 zeek 名) |
|---|---|
| conn | service / duration / orig_bytes / resp_bytes / conn_state / history / orig_pkts / resp_pkts |
| dns | query / qtype_name / rcode_name / answers / TTLs / AA / rejected |
| http | method / host / uri / user_agent / status_code / request_len / response_len / username / password / orig_mime_types / resp_filenames |
| ssl | version / cipher / server_name / subject / issuer / validation_status / ja3 / ja3s / established |
| files | filename / mime_type / total_bytes / seen_bytes / source / analyzers |
| notice | msg / note / sub / src / dst / p / actions |
| ssh | auth_success / attempts / client / server / cipher_alg / direction |
| rdp / smb_* / kerberos / ntlm | cookie / username / domain / nt_status 等(按需补) |

> logstash 的 `event.get("query")`、`event.get("uri")` 等直接可取(zeek JSON 字段平铺在顶层);`id.orig_h` 等已在信封里。

---

## 2. 双侧优化方案总览

```
输入源侧(生产方)                    智能体侧(消费方)
logstash 增加"信号字段透传"  →  EventEnvelope.enriched 增 zeek 详情
   (per-dataset 白名单 ~15 字段)     →  RuleEngine.build_unit() summary 增特征统计
                                        →  AnalysisUnit 携带:
                                           · top_queries / qtype_dist / unique_domains
                                           · top_uris / methods / status_codes
                                           · services / conn_states / bytes_sum / dur_sum
                                           · sni_set / ja3_cnt / cipher_set / filename/mime 列表
                                        →  system prompt v2(引用这些真实字段 + 强约束)
```

**顺序铁律:先输入侧落地(让 summary 有真实特征)→ 再上系统提示词 v2**(否则提示词引用的字段不存在)。

---

## 3. 输入侧优化设计

### 3.1 logstash ruby filter:增加 per-dataset 信号字段透传

在现有 `@redis.xadd(...)` 哈希里,追加 `"zeek" => 序列化后的字段子集`(只对命中白名单的 dataset 添加,控制体积):

```ruby
# 按 dataset 挑选高信号字段;只拷贝存在且非空的字段
SIGNAL_FIELDS = {
  "zeek.connection" => %w[service duration orig_bytes resp_bytes conn_state history orig_pkts resp_pkts],
  "zeek.dns"        => %w[query qtype_name rcode_name answers TTLs AA rejected],
  "zeek.http"       => %w[method host uri user_agent status_code request_len response_len username password],
  "zeek.ssl"        => %w[version cipher server_name subject issuer validation_status ja3 ja3s established],
  "zeek.files"      => %w[filename mime_type total_bytes seen_bytes source],
  "zeek.notice"     => %w[msg note sub src dst p actions],
  "zeek.ssh"        => %w[auth_success attempts client server],
}

zeek_detail = {}
(SIGNAL_FIELDS[dataset] || []).each do |f|
  v = event.get(f)
  zeek_detail[f] = v unless v.nil? || v.to_s.empty?
end
# 之后把 zeek_detail 并入 xadd 哈希(非空才加)
```
> 用 ruby 只传存在字段 → 不会撑爆;每条事件多 ~100-300B。后续如要更省,可用 zeek 日志自带 `uid` 做 ES 关联,但传输成本不高,先透传。

### 3.2 EventEnvelope 增加 `zeek` 详情容器(保留向后兼容)

- `enriched` 保持现状;新增字段 `zeek: dict = Field(default_factory=dict)`(raw zeek 信号字段;只有 logstash 更新后才会有值,旧数据为空则模型照旧走 es_search)

### 3.3 RuleEngine.build_unit() 的 summary 增特征统计

```python
# datasets / dst_ports 已有;新增(仅当 events[].zeek 有内容时)
summary = {
  "datasets": dict(datasets),
  "dst_ports": sorted(ports)[:20],
  "behavior_hits": [h.behavior_id for h in hits],
  "features": summarize_features(events),   # 按 dataset 聚合,见下表
}
```
`summarize_features` 按 dataset 产出:
- zeek.dns → `top_queries[:10]`, `unique_domains`, `qtype_dist`, `avg_entropy`
- zeek.http → `methods_dist`, `status_codes_dist`, `top_uris[:10]`(截断 80 字符)
- zeek.connection → `services_dist`, `conn_states_dist`, `bytes_sum`, `duration_sum`
- zeek.ssl → `sni_set[:10]`, `ja3_cnt`, `cipher_set[:5]`
- zeek.files → `filenames[:10]`, `mime_dist`
- zeek.notice → `msgs[:10]`
- 上限:每个 list ≤ 10 项,每项 ≤ 80 字符;无 zeek 详情 → 该键省略 → prompt 告诉模型"缺失=没透传,需 es_search"

> 这一层让 **LLM 有真实 Zeek 特征可分析**,是消除"无中生有"的基础。

---

## 4. 系统提示词 v2(纯后端 Zeek 分析引擎 · 强约束)

> 以下为 `system.md` 的 v2 提案全文。落地前提:第 3 节输入侧已完成(summary 含 features)。
> 若未落地,则本提示词引用 features 的语句需删去/改为"缺失时用 es_search"。

```markdown
# 角色(唯一)
你是 NSS-NDR(深瞳)的**纯后端安全分析引擎**,只做一件事:
把"Zeek 网络会话聚合单元(AnalysisUnit)"判定为一份结构化 JSON 安全结论。
你不是聊天助手。不生成解释、不提供处置以外建议、不输出 Markdown、不输出代码。
你没有任何 UI、没有"前一轮对话记忆",每个会话单元彼此独立。

# 你能看到什么(事实边界,严禁越界)
你能看到且**只能看到**这些:
1. `session_key` / `event_count` / `window_seconds`(本会话时间窗)
2. `summary.datasets`(各类 zeek 数据流条数)
3. `summary.dst_ports`
4. `summary.features`(若存在):按数据流给的真实特征,如
   - dns:  top_queries / unique_domains / qtype_dist / avg_entropy
   - http: methods_dist / status_codes_dist / top_uris
   - conn: services_dist / conn_states_dist / bytes_sum / duration_sum
   - ssl:  sni_set / ja3_cnt / cipher_set
   - files:filenames / mime_dist
   - notice:msgs
   (每项都来自真实 zeek 日志,**不是推断**)
5. `behavior_hits`(规则已命中,含 BEH-xxx / ATT&CK / count)
6. `initial_risk` / `rule_resolved` / `anomaly_*`(基线异常分,若非 0)
7. 工具(es_search 等)返回的结果

你**看不到**:
- 原始 zeek 日志行(每个事件只有 event_id,详情在 ES)
- 任何"可能是什么"的主观标签
- 任何不在上面列表里、也不在工具结果里的字段

# 反幻觉铁律(违反任何一条=判定失败)
1. **绝不编造** summary.features / 工具结果里不存在的:
   域名、IP、端口、URI、计数、时间戳、字节数、状态码、证书、JA3。
2. summary.features **缺失**某键(如没有 dns 特征)时:
   - 若该会话确实需要 dns 细节 → **必须调用 es_search 去取**,取不到就写
     `evidence: "细节不足,未能获取 dns 特征(工具无返回)"`,**不要自己猜**。
3. 禁止输出"可能是 X 攻击"而没有真实特征支撑的结论。
4. 若你无法从已有信息判断,输出 `verdict: "uncertain"`,`risk_level` 沿用
   `initial_risk`,并在 evidence 写明"缺什么、为什么判不了",**不硬编**。
5. 任何数值(计数/速率/字节/端口)必须与 summary/tool 一致,不允许近似杜撰。

# 分析工作流(按顺序,不可跳步)
1. 读 summary.datasets + dst_ports + features → 判断本会话在做什么协议/服务。
2. 读 behavior_hits:规则命中给的是"行为候选",你要**复核**它是否被 features 佐证;
   `rule_resolved=true` 且特征一致 → 直接输出,不重复推理。
3. 若 features 不足以判定或命中行为需要更多上下文 →
   **先 es_search**(同 src_ip + 近 1h + 对应 dataset),最多 2 次。
4. 综合 规则 + 特征 + 工具 → 判定 attack class 与 severity:
   - `low` 仅当特征全部正常或为已知误报;
   - `medium/high` 必须有**可引用的数字特征**。
5. 输出 JSON(见输出 schema),evidence 必须引用 summary/tool 里真实存在的字段。

# 严重度锚点(必须在 evidence 里给数字)
- 爆破类:失败会话数 / 失败率 / 唯一目标数
- 扫描类:唯一端口数 / 唯一目标数 / 时长
- DNS 隧道:top_queries 的熵 / 长度 / unique_domains / qtype_dist(TXT 占比)
- 数据外传:bytes_sum / duration_sum / 目的是否为罕见
- Web 攻击:top_uris 中 payload 形态 / status_codes_dist / 次数
- TLS 异常:sni_set 罕见 / ja3_cnt / cipher_set 弱套件 / validation_status

# 输出(严格)
- 仅一个 JSON;不要代码块、不要前后缀、不要 null 占位。
- verdict 用 `<attack_class>_suspected` 或 benign / uncertain / same。
- evidence 必须含至少 1 个数字,并引用字段名(如 `features.dns.top_queries[0]` 的熵)。
- 不确定就写 uncertain+缺什么,不写"low"逃避。
```

### 4.1 为什么这样设计
| 约束 | 解决 |
|---|---|
| "只能看到…/看不到…" 硬列表 | 让 0.6B 模型不越界编字段 |
| "缺失→es_search→取不到就写 uncertain" | 堵死"没有数据却硬分析" |
| evidence 必须引用真实字段 + 数字 | 让每个结论可追溯、可复核 |
| 严重度锚点给到具体特征 | 减少自由发挥的空间 |

---

## 5. 模型无法看到的 Zeek 字段 — 用 es_search 补

es_search 工具能查 ES `.ds-logs-zeek.*`(ECS 归一化字段)。system prompt 里可给一张"想查 X → 用哪个 ECS 字段/哪个 dataset"的对照表,防止模型瞎写 query:

| 要查 | ES index 片段 | 典型 ECS 字段 |
|---|---|---|
| DNS 查询详情 | zeek.dns | dns.question.name / dns.question.type / dns.resolved_ip / dns.answers |
| HTTP 详情 | zeek.http | http.request.method / http.request.uri / http.response.status_code / http.request.body.bytes |
| TLS | zeek.ssl | tls.server.name / tls.version / tls.cipher / tls.ja3 |
| 连接 | zeek.connection | network.bytes / event.duration / network.transport / zeek.connection.conn_state |
| 文件 | zeek.files | file.name / file.mime_type / file.size |
| 告警/notice | zeek.notice | zeek.notice.msg / zeek.notice.note |

---

## 6. 实施路线(分阶段,每步可独立验证)

- **Phase A(输入侧,无模型依赖)**:
  1. logstash ruby 加 SIGNAL_FIELDS 透传(改 `src/databus/logstash/pipeline/zeek-pipeline.conf`)
  2. `EventEnvelope` 加 `zeek: dict` 字段;`event_from_stream` 兼容解析
  3. `RuleEngine.build_unit` 加 `summarize_features`
  4. 重新构建 **logstash-databus + agent** 两个镜像 → CI → 服务器拉取 → 部署
  5. 验证:重跑输入调研脚本,看 summary.features 是否带真实 dns/conn 特征

- **Phase B(智能体侧)**:
  6. 用本文档第 4 节 system prompt v2 替换 `system.md`(+同步 task.md 说明 features 字段、output.md 收紧)
  7. 重建 agent 镜像 → CI → 部署
  8. 验证:对真实会话抽 verdict,evidence 里应出现可追溯到 summary.features 的字段与数字

- **Phase C(调优观测)**:
  9. 统计:verdict 分布、uncertain 占比、es_search 调用率、evidence 含数字率
  10. 校准严重度锚点(若 low 太多/误报多)

---

## 7. 风险与取舍
- 透传信号字段会增大 Redis 条目(~100-300B/条):当前流量规模可忽略;若后续高流量可改"仅透传 uid + 让 summary 在 agent 侧做 ES 批量拉取"(复杂度更高)。
- 让模型引用 features 字段名,需要字段名在 prompt 与 build_unit 里**精确一致**,否则模型会写错名(建议 Phase A 用一个固定字典,PromptBuilder 注入 features 字段名清单)。
- 0.6B 对长 features 列表可能仍会截断:features 每 list ≤ 10 项即可控。

---

## 8. 本文档配套文件
- 输入调研:`docs/research/agent-input-format.md`
- 提示词工程方法论(既有):`docs/design/prompt-engineering.md`
- 本蓝图落地后将更新 `docs/design/prompt-engineering-zeek-engine.md` 为"已落地"并记录版本
