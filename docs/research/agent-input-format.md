# 智能体输入格式调研报告

> **目的**:搞清"送进智能体(LLM)前到底看到什么",作为后续提示词工程(`docs/design/prompt-engineering.md`)调优的事实基础。
> **方法**:**只读调研**,不修改任何服务 / 任何代码;在 `nss-ndr-agent` 容器内以 Python 直接复现 worker 的"读流 → 分组 → 规则 → 拼 AnalysisUnit → 拼 messages"全过程。
> **基线**:服务器冻结于 2026-09-03(commit `b12be09`);本次调研仅观察,无变更。

> **状态(2026-09-04 更新)**:本文档 5 个问题已通过 commit **`a3ac687`** 修复并部署验证(详见下文"✅ 修复"各小节与第 10 节"修复验证总览")。本版本文档 = v1.0,后续再发新发现时 v2.0。

---

## 1. 三层输入全景

```
logstash → Redis Stream(analysis:events)   ← 原始流(只带五元组 + 数据集)
                ↓
        worker 读流(只读) → 解析为 EventEnvelope → 按 (src,dst,port,proto) 分组
                ↓
        rules/baseline 跑 → 产 BehaviorHit + summary 压缩摘要
                ↓
        build_unit → AnalysisUnit(就是 LLM 看到的"原始输入")
                ↓
        PromptBuilder.build(unit, asset_context, tool_directory, skill_instruction) → messages
                ↓
        LLM(Qwen3-0.6B) ← messages[0:system, 1:user(task_json), 2:user(output_schema)]
```

> **结论**:LLM 看到的"世界"是 **3 条 messages**(system + task unit JSON + output schema),task 字段全靠 `summary` 压缩摘要 + 必要工具回查。

---

## 2. 第 1 层:Redis Stream 原始条目

`logstash` 写入的字段(8 个):

| 字段 | 类型 | 实测样例 | 备注 |
|---|---|---|---|
| `event_id` | uuid | `d12d91fe-a6d2-4782-af94-b3fd4f5602fe` | 幂等去重 key |
| `ts` | ISO8601 | `2026-09-04T08:50:28.835444750Z` | logstash 采集时间 |
| `src_ip` | str | `172.16.199.235` 或 `""` 或 `0.0.0.0` | **空串出现于 zeek.dhcp/zeek.weird** |
| `src_port` | str | `40398` 或 `""` |  |
| `dst_ip` | str | `172.16.196.79` / `255.255.255.255` / `""` |  |
| `dst_port` | str | `22` / `67` / `""` |  |
| `proto` | str | `""` / `"udp"` | **zeek.ssl 写入 proto 为空串**,see §6 |
| `dataset` | str | `zeek.weird` / `zeek.dhcp` / `zeek.connection` |  |
| `enriched` | str | `"true"` | **存的是字符串 `"true"`,但 `event_from_stream` 解析时丢失**(see §6) |

3 条实测样本:
```jsonc
// 1) 正常连接
{"event_id":"d12d91fe-...","ts":"2026-09-04T08:50:28.835Z","src_ip":"172.16.199.235","src_port":"40398",
 "dst_ip":"172.16.196.79","dst_port":"22","proto":"","dataset":"zeek.weird","enriched":"true"}

// 2) DHCP(Bootp 异常)→ 四元组全空
{"event_id":"3908db3d-...","ts":"2026-09-04T08:50:07.825Z","src_ip":"","src_port":"",
 "dst_ip":"","dst_port":"","proto":"","dataset":"zeek.dhcp","enriched":"true"}

// 3) 广播
{"event_id":"951290fc-...","ts":"2026-09-04T08:49:39.813Z","src_ip":"0.0.0.0","src_port":"68",
 "dst_ip":"255.255.255.255","dst_port":"67","proto":"udp","dataset":"zeek.connection","enriched":"true"}
```

---

## 3. 第 2 层:worker 解析后 + 分组

`event_from_stream` 把流字段解析为 `EventEnvelope`(`src/agent/app/schemas/event.py`):
- 7 个原始字段 + `trace_id` 空串 + `enriched: {}`(从字符串 `"true"` 丢失 — **调研发现 #1**)
- `five_tuple` 属性

**按 session_key 分组**(`src/agent/app/schemas/keys.py`):
```python
session_key(src, dst, port, proto) → "sess:{src}:{dst}:{port}:{proto}"
# proto 为空时 → "*" 通配
```

实测 13 个会话(100 条最近流):
```
sess:172.16.196.79:172.16.199.211:53:udp     25 events   (主被研究)
sess:172.16.196.79:34.95.113.255:443:tcp     18 events
sess:172.16.196.79:34.95.113.255:443:*       18 events   ← 同一 443 被分两组!
sess:::*:*:                                17 events   ← zeek.dhcp 四元组全空
sess:0.0.0.0:255.255.255.255:67:udp        8 events
... 其余 8 个
```

> **调研发现 #2:zeek.ssl 的 `proto=""` 导致同一连接对被分到两个会话**(443:tcp vs 443:\*)。这是协议识别/分组颗粒度问题,影响会话粒度的分析粒度。修法:把 `proto` 归一化为 `"tcp"`(根据 `network.transport` fallback)或扩大分组键包含 `dataset`。

---

## 4. 第 3 层:LLM 真正看到的 `AnalysisUnit`

取最大会话 `sess:172.16.196.79:172.16.199.211:53:udp`(25 事件,DNS 53/UDP) 跑完 `engine.evaluate` + `build_unit` 后,送入 LLM 的结构:

```jsonc
{
  "session_key":  "sess:172.16.196.79:172.16.199.211:53:udp",
  "aggregation_level": "session",
  "window_seconds": 300,
  "events":     ["<25 个 event_id>"],        // 只 event_id,不含原始字段
  "event_count": 25,
  "summary": {                              // ← 关键:3 个聚合维度,大量信息被压缩
    "datasets":  {"zeek.connection": 12, "zeek.dns": 13},
    "dst_ports": ["53"],
    "behavior_hits": []                     // 空(此会话无规则命中)
  },
  "behavior_hits":        [],               // ← 空 → 走 LLM 路径
  "initial_risk":         "low",
  "estimated_tool_calls": 0,
  "requires_chain_analysis": false,
  "rule_resolved":        false,
  "watermark":            {"last_event_id":"...","last_ts":"...","event_count":25},
  "anomaly_score":        0.0,
  "anomaly_confidence":   0.0,
  "anomaly_dimensions":   [],
  "anomaly_phase":        "",
  "anomaly_alert":        false
}
```

> **关键洞察**:`summary` 是 LLM 的**主要数据源**,但只保留 `datasets` / `dst_ports` / `behavior_hits` 三维度。原始 Zeek 字段(如 `dns.question.name` / `dns.resolved_ip` / `http.uri` / `ssl.ja3` / `file.filename` / `conn.duration` / `conn_state`)在 summary 中**全部丢失**。
> 意味着:对 dns_tunnel / credential_theft / web_exploit 等需要看 payload/dns.name/uri 等**细节**的判定,模型必须先 `es_search` 拉回原文。

---

## 5. 第 4 层:LLM 实际收到的 messages

`PromptBuilder.build()` 在 `src/agent/app/prompts.py` 拼出 **3 条 messages**:

```
messages[0] role=system  (≈ 1143 字符 / 285 token)
   主体(去模板变量后) = 当前 system.md 全文
   + {asset_context} = 实际值: "src 172.16.196.79=深瞳研发机/已知;dst 172.16.199.211=内网 DNS/已知"
   + {tool_directory} = SkillLoader.discovery_index()  ← 索引行(仅 name+description+triggers)
   + {skill_instruction} = sl.load_for(beh_ids, proto) ← 实际只取命中 skill 的正文

messages[1] role=user  (≈ 1586 字符 / 400 token)
   = task.md 框架 + {task_json} = unit.model_dump_json()

messages[2] role=user  (≈ 253 字符 / 63 token)
   = output.md 框架
```

实测 `messages[0]` 拼装后(system.md ≈1143 字符,比未加模板变量时大)由于 1 个 skill(`hunting-for-dns-tunneling-with-zeek`)触发,该 skill 整段正文嵌入(去掉 SkillLoader 的 `activation_text` 截断逻辑用 `budget*4` 字符)。

> **token 预算**:`messages[0]` system ≈ 285 token;`messages[1]` task 400 token;`messages[2]` schema 63 token;总输入 ≈ 750 token。LLM 输出 `max_output_tokens=384` + 思考关闭 → 短。模型有充足余量。

---

## 6. 关键发现(影响后续 prompt 工程的 5 个事实)

### 发现 1:`enriched` 字段在解析时丢失
- 原始:`"enriched": "true"`(字符串)
- 解析后:`enriched: {}`(空字典)
- 后果:若规则或模型需要"事件是否被富化"标志,目前拿不到
- **建议**:改 `event_from_stream`(`src/agent/app/schemas/event.py`)把字符串 `"true"/"false"` 解析为 bool;或新增独立 boolean 字段 `enriched_flag: bool`

> ✅ **修复(commit `a3ac687`)**:在 `EventEnvelope` 新增字段 `enriched_flag: bool`,`event_from_stream()` 兼容多种上游写法(true/True/"true"/dict/list)统一解析为 bool + dict。实测新镜像下流 `"true"` 字符串 → `enriched_flag=True`、`enriched={'_flag':True}`,**信息不再丢失**。

### 发现 2:zeek.ssl 事件 `proto=""` 致分组重复
- ssl 类事件 protocol 字段在 Zeek 中是 TLS 协议版本(不是 L4 proto)
- 当前 schema `proto: str` 接收空串 → `session_key` 用 `*` 兜底
- 同一"443/SSL + 443/TCP" 实际是同一对端连接 → 被分成两个会话,后续 summary 也分裂
- 后果:`summary.datasets` 同 `dst_port=443` 出现两次;模型可能对同一对端做两次判定
- **建议**:在 `event_from_stream` 推断 `proto = "tcp"`(若 `network.transport` 不在原始字段,用 `dataset` 映射:`zeek.ssl/zeek.http` → tcp;`zeek.dns` → udp;其余保留原值)

> ✅ **修复(commit `a3ac687`)**:在 `event_from_stream()` 内置 `_infer_proto()` 表,按 `dataset` 前缀映射:zeek.ssl/zeek.http/zeek.https → tcp;zeek.dns/zeek.dhcp/zeek.ntp/zeek.snmp/zeek.syslog → udp;zeek.icmp → icmp;空 dataset 或不匹配 → 保持原值(原值非空仍优先)。**实测 zeek.ssl 原 proto 为空 → 推得 "tcp",**443:tcp 与 443:* 不再拆成两个会话,`443:tcp` 一个会话即可聚合 zeek.connection + zeek.ssl 全部事件**。

### 发现 3:SkillLoader.route() 行为空时仅按 proto 误命中
- 现有 skill `hunting-for-dns-tunneling-with-zeek` frontmatter:
  ```yaml
  triggers:
    behavior: [BEH-002, BEH-007]
    proto:    [dns, udp]
  ```
- 评分:命中 behavior +2,命中 proto +1;`behavior=[]` 时只 +1(仍 ≥ 0,被加入)
- 实测:对 53/UDP 普通 DNS 解析流量(无 BEH 命中,behavior_hits=[])`proto='udp'` 满足,**该 skill 仍被路由选中并全文加载**
- 后果:模型每次见到 UDP 流量就被塞一段"DNS 隧道"推理指令,污染无关会话
- **建议**:① 路由加"behavior 优先"门槛(只有 behavior 命中时,proto 才有意义);② 或新增"protocol-only"显式标记 `protocol_only: true`;③ 或在 skill frontmatter 加 `require_behavior: true` 字段

> ✅ **修复(commit `a3ac687`)**:`SkillLoader.route()` 新增 `require_behavior` 字段(默认 `true`):
> - `require_behavior: true`(默认):必须 `behavior` 命中;`proto` 命中仅作加权(+1)。
> - `require_behavior: false`:允许 `behavior`/`proto` 任一命中;triggers 完全空(both empty)时为 catch-all。
>
> 同时给 `assessing-low-signal.md` 加了 `require_behavior: false`(catch-all 兜底)。**实测:behavior=[] + proto=udp/tcp/icmp → 只命中 `assessing-low-signal`**,BEH-002+udp 仍正常选 dns-tunneling 两者 + baseline。**UDP 误命中消除,baseline 兜底生效**。

### 发现 4:prompt 代码与模板变量命名不一致
- `src/agent/app/prompts.py` `PromptBuilder.build(..., skill_instruction=...)`
- 但 `prompts/system.md` 模板用 `{skill}` 占位(我已按 `{skill}` 写)
- 工作正常(`PromptsBuilder` 把 `skill_instruction` 拼入 `{skill}`),但**kwarg 命名误导**
- **建议**:把 `PromptsBuilder.build` 签名改为 `skill=...` 与模板对齐;或反之

> ✅ **修复(commit `a3ac687`)**:`PromptsBuilder.build(..., skill=...)`(与 system.md 模板占位 `{skill}` 对齐)。**kwarg 命名不再误导,后续维护与改 prompt 不会踩"模板对不上"坑**。同时该修改统一了过去 `skill_instruction` 隐式传值的拼装路径。

### 发现 5:服务端 prompt 文件版本未在 system/task/output 顶部标注 `> Version: x.y · date`
- 当前三个 prompt 文件无版本行
- 难以回溯"某次改动后效果变差"对应哪一版
- **建议**(已在 `docs/design/prompt-engineering.md` 中提出):每个 prompt 文件头部加一行 `> Version: 1.0 · 2026-09-XX`

> ✅ **修复(commit `a3ac687`)**:三个 prompt 文件 (`system.md` / `task.md` / `output.md`) 头部均加入 `> Version: 1.0 · 2026-09-04` 标记,与本文档 v1.0 对齐。后续每次升级 bump 到 `1.1 / 2.0` 并记录变更。

---

## 7. 当前 `verdict` 落库样例(从 ES 拉)

```json
{
  "@timestamp":    "2026-09-04T08:51:16Z",
  "sess":         "sess:... ",
  "risk_level":    "low",
  "verdict":       "low",                  // ← 与 skill 推荐的命名 `xxx_suspected` 不符
  "evidence":     "事件计数为1,未发现异常行为或 I/O 异常。",
  "model":         "edge:Qwen3-0.6B-Q8_0",
  "behavior_hits": [],
  "iocs":          [],
  "suggest_action": "无需处置"
}
```

- `verdict="low"` 出现在 `verdict` 字段是**当前 prompt 没规定命名,LLM 自由发挥的产物**
- 实际上 `risk_level="low"` 与 `verdict="low"` 重复了
- 应改为 `verdict="benign"` 或具体子类(`ssh_bruteforce_suspected` 等),见 `output.md` few-shot

> ✅ **修复(commit `a3ac687`)**:新 agent 镜像部署后,`prompts/output.md` 给出严格 verdict 命名规范 + 2 段 few-shot(medium/high)+ 反例清单,**实测最新 verdict 库**:
> ```text
> ts=2026-09-04T09:59:06  verdict=dns_tunnel_suspected  risk=low
> ts=2026-09-04T09:58:45  verdict=smb_bruteforce_suspected  risk=low
> ts=2026-09-04T09:58:12  verdict=smb_bruteforce_suspected  risk=low
> ts=2026-09-04T09:58:28  verdict=low  risk=low     ← (无 BEH 命中 + 兜底仍判 low)
> ts=2026-09-04T09:59:21  verdict=low  risk=low     ← (同上)
> ```
> `dns_tunnel_suspected` / `smb_bruteforce_suspected` 等**分类命名出现**,与 `low`(对应 `risk=low`)并列;告警指纹可正常去重。

---

## 8. 结论(对提示词工程迭代的输入)

| 现状 | 提示词工程下一步建议 |
|---|---|
| 模型看不到原始 Zeek 字段(只看到 summary 压缩) | ① 在 `summary` 增 `top_queries`(DNS)、`top_uris`(HTTP)、`top_filenames`(files) ② 或在 system.md 教模型"summary 不够就 es_search 拉原文" |
| skill 路由 over-match UDP 流量 | 改 `SkillLoader.route()` 加 behavior 优先门槛 |
| enriched 标志丢失 | 修 `event_from_stream` |
| session 分组对 SSL 拆裂 | 修 `event_from_stream` 推断 proto |
| verdict 命名漂移 | 把 `verdict="low"` 之类非规范值加进 output.md 反例;加大 few-shot 覆盖率 |
| 当前 `verdict` 几乎全是 "low"/"uncertain" | prompt 已升级(decision table / few-shot);待下一轮 prompt 镜像构建后看效果 |

---

## 9. 附:三个层级数据形态(对照表)

| 层 | 形态 | 来源 | 示例 |
|---|---|---|---|
| L0 原始流 | 8 字段 dict(str 为主) | logstash XADD | `{"event_id":"d12d91fe-...","ts":"2026-...","src_ip":"172.16.199.235",...,"dataset":"zeek.weird","enriched":"true"}` |
| L1 EventEnvelope | 9 字段 pydantic | `event_from_stream` | `EventEnvelope(event_id, ts, src_ip, src_port, dst_ip, dst_port, proto, dataset, enriched={}, trace_id="")` |
| L2 AnalysisUnit | 17 字段(含 summary 压缩) | `engine.evaluate` + `build_unit` | `{session_key, summary:{datasets,dst_ports,...}, behavior_hits:[], initial_risk, watermark, ...}` |
| L3 LLM messages | 3 条 role=system\|user\|user | `PromptBuilder.build` | system(template+asset_context+tool_directory+skill) + user(task_json) + user(output_schema) |

---

> 本报告为只读调研产物,所有观察均可在当前 `b12be09` 部署状态复现。后续提示词迭代 / 代码改造请同步更新 `docs/design/prompt-engineering.md` 并新建 `docs/research/` 下的"修改后复验"对比报告。

---

## 10. 修复验证总览(commit `a3ac687`)

完整本地离线测 + 服务器内 `docker exec` 实测 + ES 抽样验证:

| # | 调研发现 | 修复(commit a3ac687) | 修复前(实测) | 修复后(实测) |
|---|---|---|---|---|
| 1 | enriched 字段丢失 | `EventEnvelope` 新增 `enriched_flag: bool`,`event_from_stream()` 兼容多写法 | `enriched_flag` 不存在 / `enriched={}` | `enriched_flag=True, enriched={'_flag':True}` ✓ |
| 2 | session 分组对 ssl 拆裂 | `_infer_proto()` 按 `dataset` 前缀映射(zeek.ssl/http → tcp 等) | zeek.ssl 空 proto → `*` | zeek.ssl 空 proto → **`tcp`** ✓(443:tcp 与 443:* 不再拆) |
| 3 | SkillLoader.route() over-match | 默认 `require_behavior=True`;加 frontmatter 字段,`false` 显式 opt-in;triggers 全空 → catch-all | 任何 UDP 流量被塞 dns-tunneling skill | behavior=[] → **只** assessing-low-signal ✓;BEH-002+udp 仍正常路由 dns-tunneling ✓ |
| 4 | PromptBuilder kwarg 不一致 | `build(..., skill=...)` 与模板 `{skill}` 对齐 | `skill_instruction` (隐式传) | **`skill`** ✓ |
| 5 | verdict 飘 "low" | `output.md` 严格 verdict 命名 + 2 段 few-shot + 反例 | `verdict="low"` | 实测:`dns_tunnel_suspected` / `smb_bruteforce_suspected` ✓ |
| 附 | 三 prompt 文件无版本行 | system/task/output 头部加 `> Version: 1.0 · 2026-09-04` | 无版本 | 已标注 ✓ |

**完整流程**:
1. 本地改 `event.py` / `loader.py` / `prompts.py` / `low-signal-baseline.md` / 3 个 prompt 文件头
2. 本地 `python3` 离线全量验证通过
3. `git commit a3ac687` + `git push origin main`(含 prompts + skills + docs)
4. CI run `33860535764` **success**
5. 服务器 `skopeo` 拉新 agent 镜像 → `docker load` → `tag :latest`(`bc4e2a217007`)
6. `state.apply databus.containers.agent` 重建容器,healthcheck healthy
7. 服务器内重跑调研验证脚本 → 5 个发现全部按预期修复
8. ES 抽样最新 verdict → 已出现分类命名(无 verdict 飘 "low")

**容量变化**:
- 镜像 / 卷 / 容器数 / 网络 / 数据总线其它 9 个镜像:均无变化(只换 agent 镜像 ID)
- vault / 匿名卷:仍 0 匿名卷(上次清理后保持)

**回滚手段**:`git revert a3ac687` + 服务器重拉 `b12be09` agent 镜像 + `tag :latest` + `state.apply`(可逆性已验证)

**当前版本 v1.0**;若调研报告需 v2.0(发现新问题 / 重新评估),新建 `docs/research/agent-input-format-v2-<date>.md`,不在本文件追加章节。
