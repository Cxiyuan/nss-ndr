# NSS-NDR 智能体提示词工程设计文档

> **目的**:把"如何为本项目设计、演进、运维提示词(prompts)与技能(skills)"作为可重复执行的方法沉淀下来,让任何新成员或后续 Agent 开发都能按同一规范工作,避免每次改提示词都要重新摸黑。
> **范围**:`src/agent/prompts/{system, task, output}.md` + `src/agent/skills/*.md` 的设计、演进、测试、发布与维护。
> **受众**:Agent 开发者、安全分析师(业务知识方)、SRE/平台。
> **版本**:`1.0` · 首次建立方法论,基线 prompts/skills 来自 `system/task/output` 三件套 + 12 个 BEH-001..012 技能。

---

## 1. 目标与定位(Why)

### 1.1 业务定位
- NSS-NDR 是**面向 NDR 流量侧**的**离线异步 AI 法官**:Zeek 解析的 conn/dns/http/ssl/files 日志经 logstash 入 Redis Stream,智能体逐会话(`(src_ip, dst_ip, dst_port, proto)`)聚合分析,产出 verdict → Redis 缓存 + ES 双写 + 告警/处置建议。
- 智能体不是聊天机器人,不是威胁情报检索器,不是 SOAR 自动化器。**唯一职责**:对 AnalysisUnit 给出结构化 JSON 判定。

### 1.2 为什么需要专门的提示词工程(而不是"通用 prompt")
| 约束 | 推论 | 对提示词的要求 |
|---|---|---|
| 模型 = **Qwen3-0.6B-Q8**(本地 llama.cpp) | 小模型,指令跟随弱、易幻觉、CoT 冗长 | **强显式 persona + few-shot + 严格 JSON schema + 反幻觉纪律** |
| 思考模式默认开(`enable_thinking=true`) | 单次思考可吃掉全部 384 输出 token,致解析失败 | 强制 `chat_template_kwargs.enable_thinking=false` |
| 上下文窗口 6144 token(parallel 2 → slot 3072) | 不能塞长历史 | **Skill 上下文预算 ≤ 1500 token,工具调用 ≤ 2 次** |
| 工具 5 个,均为 ES/Redis 读类 | 易被模型当成"答案"复述 | **明文强调"工具=放大镜,不是抄写源"** |
| 输出必须能进 Redis 缓存 + ES 历史 | 字段改名/丢字段 = 系统级故障 | **schema 与 `Verdict` pydantic 字段严格一致** |
| 规则引擎已先做粗筛(BEH-001..012) | 模型不要重复,做"研判补强" | **明确"rule_resolved=true 时输出简短 verdict 即可"** |
| 同一会话 1h 内同 watermark 会**缓存复用** | 模型不应重复推理 | 提到 reused 语义,避免误输出新结论 |

### 1.3 与"代码/规则"的责任边界(关键,后续不要踩)
| 层 | 谁负责 | 不该混进提示词 |
|---|---|---|
| 抓包 → ES | Zeek + elastic-agent | — |
| 抓包 → Redis | logstash | — |
| 规则命中 | `src/agent/rules/beh-rules.yaml` + `RuleEngine` | prompt 不该重复规则的匹配逻辑 |
| 异常评分 | `BaselineEngine` | prompt 不该重算 |
| **研判补强 + 工具调度 + 升级 + JSON verdict** | **LLM(prompt 是它的脚手架)** | — |
| 写 ES/Redis | `verdict_write` 节点 | prompt 不该规定怎么写 |
| 告警/联动 | `alert` 节点 + 外部 | — |

> **铁律**:prompt 只"指导 LLM 怎么想",不"指挥 LLM 替系统干别的活"。任何"绕过规则/绕过落库"的口吻都应删掉。

---

## 2. 设计原则(可作为 review checklist)

每条原则都配"落地形态"与"反例"。

### 2.1 显式优于隐式(对 0.6B 模型尤其重要)
- 显式 persona、显式任务、显式输出契约、显式反例清单
- ❌ "你应该给出风险等级" → ✅ "你必须输出 `risk_level` ∈ {low, medium, high}"

### 2.2 三层职责不重叠(系统/任务/输出)
- **system**: 角色、上下文、工具、严重度参考、输出硬要求、反幻觉
- **task**: 当前单元是什么、字段含义、你要做什么、不要做什么
- **output**: 仅 JSON schema + few-shot + 反例
- ❌ 在 task.md 里写严重度表(应放 system.md)
- ❌ 在 system.md 里贴 JSON schema 全文(应放 output.md)

### 2.3 Few-shot 优先于"自然语言长描述"
- Qwen3-0.6B 对结构化示例最稳
- 每个 skill 自带 1 段 JSON 输出示例;output.md 给 2 段(覆盖 medium 与 high 各 1)
- 严禁在 few-shot 里出现虚构/敏感数据,用脱敏占位(`10.0.0.x`、`<query_name 示例>`)

### 2.4 上下文预算(budget)硬约束
- 单次会话总上下文 ≤ 3072 token(slot 2048 的中间)
- Skill `context_budget` 是字符预算(`activation_text` 截断 ≈ `budget*4` 字符)
- 系统提示词 ≤ ~1200 token
- 工具调用结果在 prompt 中要被截断(256 token default),模型看不到"工具全文"

### 2.5 决定论(Determinism)
- 相同输入 + 相同 watermark + 1h 缓存窗口 → **严格复用**(由代码保证,prompt 不必管)
- 同一会话新事件触发时,提示词强调"基于新 watermark 给结论,不要覆盖复用"
- ❌ 引入"随机"或"建议"等可能让模型产生不可复现输出的措辞

### 2.6 反幻觉(对 LLM 在安全场景的底线)
- 提示词明确禁止捏造 IP/域名/时间戳/计数
- 工具结果若超时/空,标注 "(无返回)" 不许凭空补全
- 拒绝把 high 降为 low 除非有强证据
- iocs / evidence 字段若仅基于推理,必须显式说"基于 … 推断"

### 2.7 可测试(下游测试章节)
- 每个输出示例应是"输入 AnalysisUnit JSON → 期望 verdict"的测试用例
- 每个 skill 的 `triggers` 是机器可读的(便于 CI 做"触发命中"断言)
- 输出 schema 是**唯一权威**,prompt 中任何对字段的措辞与 `Verdict` 模型不一致必须修

### 2.8 可演进(关键)
- skill 文件名 + `triggers` + frontmatter = 该 skill 的"接口契约",改它要遵循语义版本
- system.md 里的"严重度参考"是软建议(可按季度校准)
- output.md 的 JSON schema 与 `schemas/verdict.py` **强绑定**,改 schema 必须同步改 output.md 并 bump version

---

## 3. 资产与契约(提示词不能动这些)

> **铁律**:`Verdict` / `AnalysisUnit` / `EventEnvelope` / `Skill` / `iocs[].type` 是**系统契约**。prompt 只能"教 LLM 怎么用",不能"修改定义"。

### 3.1 Verdict(Verdict 必含字段)
| 字段 | 类型 | 来源 | 在 prompt 中的角色 |
|---|---|---|---|
| `risk_level` | low\|medium\|high | 必填 | 在 system.md/output.md 中"严重度参考" |
| `verdict` | str snake_case `<attack>_suspected`\|benign\|same\|uncertain | 必填 | system.md 给出命名清单 |
| `evidence` | str 必须含数字 | 必填 | system.md + output.md 示例 |
| `iocs` | list[dict] | 必填(可空[]) | output.md 给出 `type` 枚举 |
| `suggest_action` | str | 必填(可"") | system.md "判定策略" |
| `behavior_hits` | list[str] | 已有,prompt 只读 | system.md 强调"基于这些继续研判" |
| `model` | str | 已有 | 透明字段,prompt 不需提 |
| `truncated` | bool | 已有 | 工具结果截断标记 |
| `watermark` | dict | 已有 | prompt 提"水位"语义 |
| `trace_id` | str | 已有 | 透明 |
| `created_at` | str | 已有 | 透明 |
| `ver` | int | 已有 | 透明,版本 |

### 3.2 AnalysisUnit(任务输入)
- 关键字段:`session_key` / `summary` / `event_count` / `behavior_hits` / `initial_risk` / `rule_resolved` / `estimated_tool_calls` / `requires_chain_analysis` / `anomaly_*` / `watermark`
- prompt 的 task.md 给字段含义表,而非解释 schema 定义

### 3.3 Skill(技能子机制)
- 文件 = yaml frontmatter + markdown body
- frontmatter 字段(机器可读):`name` / `description` / `version` / `triggers:{proto, behavior, keyword}` / `context_budget` / `mcp_tools` / `outputs`
- body = 目标 + 步骤 + 阈值 + JSON 示例
- **`behavior` 列表** 必须与 `beh-rules.yaml` 中的 `- id: BEH-xxx` 一一对应

### 3.4 EventEnvelope(模型不可见原始字段,但 system.md 应说明数据语境)
- 模型看不到原始 Zeek 字段,只能从 `summary` 与 `es_search` 工具读
- 但 system.md 应说明"存在哪些字段/类型",以避免模型胡编字段名

---

## 4. 三层提示词架构

### 4.1 `system.md`(角色、上下文、原则、参考)
**放什么**
- Persona / 职责边界(3 件事:判风险、调工具、出 JSON)
- 数据语境(Zeek 数据流 / 关键字段 / 字段含义)
- 工具原则(≤ 2 次调用;不确定才调)
- 判定策略(verdict 命名规范、严重度参考表)
- 输出硬要求(JSON 唯一、必填、字段命名、Few-shot 提示)
- 反幻觉(不捏造、不反向推翻)

**不放什么**
- 当前 case 的具体数据(那是 task.md 的事)
- 输出 schema 全文(那是 output.md 的事)
- 工具调用的具体语法/参数(工具定义文件已经负责)

### 4.2 `task.md`(本单元是什么、你要做什么)
**放什么**
- `AnalysisUnit` 字段说明表(用一列含义 / 一列用途)
- "你要做 3 件事"清单
- "注意"(缓存命中 / 不查无关行为 / 时间窗 / 速率而非累计)

**不放什么**
- 数据集大小
- 任何 Verdict 字段的 schema 描述

### 4.3 `output.md`(JSON schema + few-shot)
**放什么**
- 字段表 + 类型 / 含义 / 必填性
- `iocs[].type` 枚举
- 2 段 few-shot: medium 1 + high 1(覆盖主要路径)
- 反例(禁止项)清单

**不放什么**
- 角色 / 上下文
- 任何解释"为什么这样输出"的散文

### 4.4 模板变量(必须与 `nodes.py` 一致)
| 变量 | 注入位置 | 来源 |
|---|---|---|
| `{asset_context}` | system.md | `AssetKB.context_for([src,dst])` |
| `{tool_directory}` | system.md | `ToolRegistry.directory()` |
| `{skill}` | system.md | `SkillLoader.load_for(behavior_ids, proto)` |
| `{task_json}` | task.md | `AnalysisUnit.model_dump_json()` |
- 任何 prompt 里出现 `{...}` 必须在 `nodes.py` 的 `PromptBuilder.build` / `model` 节点里能匹配到

---

## 5. Skills 子机制

### 5.1 frontmatter 契约(必填,机器可读)
```yaml
---
name: <kebab-case>             # 全局唯一,稳定
description: <一句话, 索引用>     # Layer1 常驻系统提示词的索引行
version: "1.x"                 # 修订就改
triggers:
  proto: [tcp, dns, ...]       # 协议触发;空表 = 任何协议
  behavior: [BEH-001, BEH-007]  # 行为 ID 触发;空表 = 任何行为
  keyword: [dns_tunnel, ...]    # 自由关键词(轻辅助,可空)
context_budget: 1500           # 字符预算(≈ token×4)
mcp_tools: [query_peer_relations, ...]   # 提示模型优先用的工具
outputs: [risk_level, verdict, ...]      # 该技能通常填的字段
---
```
- `name` 全局唯一,改它要小心(会失忆已加载引用)
- `triggers.behavior` **必须**与 `beh-rules.yaml` 的 `id` 对齐
- `context_budget` 是裁断阈值,不要超过 `3000`(`activation_text` 大约 12k 字符会撑爆)

### 5.2 路由与加载(`SkillLoader.route()`)
- 三路评分 `behavior` 命中 +2、`proto` 命中 +1;按 score 排序取 Top-3,实际激活只取 Top-2
- proto 触发但 behavior 空 → 仍然可命中(只 +1),适合"协议级"技能(如 anomalous-outbound)
- 反向语义:`triggers` 空 = 不被任何会话选中(慎用)

### 5.3 body 写法
- 目标(1-2 句)
- 步骤(3-6 条,每条一行,可调工具列表)
- 判定阈值(low/medium/high,具体数字)
- JSON 输出示例(必给,直接照搬到 schema)
- 严禁在 body 里说"我建议你..."等自由发挥语句,必须给硬规则

### 5.4 当前技能覆盖矩阵
| Skill | 触发 | 行为 | 严重度趋势 |
|---|---|---|---|
| `smb-lateral-movement` | tcp / BEH-001 | 横向 SMB 爆破 | med / high |
| `dns-tunneling` | dns,udp / BEH-002, BEH-007 | C2/DNS 隧道 | med / high |
| `web-login-bruteforce` | tcp / BEH-003 | Web 登录撞库 | med / high |
| `data-exfiltration` | tcp,tls / BEH-004 | 数据外传 | med / high |
| `port-scan` | tcp,udp,icmp / BEH-005 | 端口扫描 | med / high |
| `ssh-bruteforce` | tcp / BEH-006 | SSH 爆破 | med / high |
| `dns-tunnel` | dns,udp / BEH-002, BEH-007 | (旧) 合并到 `dns-tunneling`,可下线 | — |
| `web-exploit-attempt` | tcp / BEH-008 | Web 漏洞利用尝试 | med / high |
| `anomalous-outbound` | tcp,udp / BEH-009 | 异常出向 | med / high |
| `credential-theft` | tcp / BEH-010 | 凭据窃取 | med / high |
| `privilege-escalation` | (协议空) / BEH-011 | 提权尝试 | high |
| `rdp-bruteforce` | tcp / BEH-012 | RDP 爆破 | med / high |
| `low-signal-baseline` | (任意) / (无) | 无规则命中兜底 | low → benign |

> 维护注意:`dns-tunnel.md` 与 `dns-tunneling.md` 行为重叠 → 后续清理下线前者,保持 1 行为 1 技能。

---

## 6. 与其它子系统的协同

### 6.1 与规则引擎(`beh-rules.yaml` + `RuleEngine`)
- 规则决定是否进 LLM(`rule_resolved && behavior_hits` → 直接 verdict_write 跳过 LLM)
- 规则的 `id` 是 prompt 中 skill 路由的"地址"
- 新增/修改规则 → 必同步:① schema (output.md 中 verdict 命名) ② skill frontmatter 的 `triggers.behavior`
- 规则初判等级 `initial_risk` 是 LLM 起点;**不要在 prompt 中要求"重判 initial_risk"**,应"沿用或升级"

### 6.2 与工具(MCP)
- 工具 `parameters` schema 由 `openai_compat.py` 决定;prompt 不再写"工具参数语法"
- prompt 限制:`max_tool_calls=2`;工具结果由 `truncate_result` 在 prompt 中截断
- 工具异常(超时/空)必须在 prompt 里被显式标注"不返回(无返回)";LLM 不应编造结果

### 6.3 与升级(`escalate_check` / `needs_cloud`)
- `needs_cloud` 是**硬规则**(initial/local risk=high、行为 ≥2、uncertain、chain analysis、anomaly_alert)
- prompt 不应"建议升级",而是"当硬规则命中时,模型走 cloud 路径自动判定" → **在 prompt 中不写升级字眼,只写"判得准"**

### 6.4 与告警/指纹(`alert_fingerprint`)
- 告警去重由代码(`(sess, verdict, sorted(behavior_hits))` SHA1)负责
- prompt 不要写"避免重复告警",应写"verdict 命名要稳定"(`smb_bruteforce_suspected` 一致即可被指纹合并)

### 6.5 与缓存(`result_ttl=3600` + watermark)
- 1h 内同会话同 watermark 复用 → 模型在 1h 内的重复请求**不会再次跑推理**
- prompt 应告诉模型"如果你看到 reused=true,直接复用结果"——但不强制写"verdict: same"(代码会自动写 `same`)

---

## 7. 生命周期与版本

### 7.1 三阶段
1. **草稿 (DRAFT)**:在 `prompts/` 与 `skills/` 直接改,本地手测(后面 §9)
2. **灰度 (SHADOW)**:与 prod prompt 并行跑(N 副本)一段周期;通过质量指标对比
3. **发布 (PROD)**:状态合并入主 prompt 文件,旧版保留在 `git` 历史中,文件名不变

### 7.2 版本号
- skill frontmatter `version: "1.x"`,重大行为变更 bump 小版本
- output.md / system.md / task.md 顶部加一行 `> Version: 1.0 · YYYY-MM-DD`(便于回溯)
- 旧版通过 git tag 或 commit 找回

### 7.3 CI 静态检查(应做,尚未实现)
- 所有 `*.md` 文件有可解析 frontmatter(YAML 合法)
- `triggers.behavior` 元素都在 `beh-rules.yaml` 中存在
- `verdict` 字段集合在 system.md / output.md / 各 skill 示例中**完全一致**
- `iocs[].type` 在各 skill 示例中的值都在 output.md 枚举里
- 模板变量 `{...}` 集合与 `nodes.py` 注入的占位集合一一对应

---

## 8. 质量度量

### 8.1 静态(每次 PR 必跑)
- frontmatter YAML 合法
- `triggers.behavior` 引用合法
- verdict 字符串只在 `output.md` 枚举内
- `outputs` 字段与 Verdict 字段对齐
- `iocs[].type` 在枚举内
- `context_budget` ≤ 3000
- `mcp_tools` 全部在 `tools.py` 中已注册

### 8.2 动态(运行时,持续观测)
| 指标 | 期望 | 异常阈值 |
|---|---|---|
| verdict 解析失败率(`verdict=uncertain/parse fail`) | < 5% | > 10% |
| verdict=uncertain / 总量 | < 8% | > 15% |
| 高风险占比 | 监控基线,异常偏离 ±30% | 跳变 |
| verdict 在 1h 内被复用率(reused=true/总量) | > 30% | < 10% 表明缓存没起作用 |
| events.dedup 触发率(重复事件跳过) | 监控基线 | 突增 = 上游 XADD 重复 |
| 工具调用平均次数 / session | < 1.0 | > 1.5 |
| 工具调用失败率 | < 1% | > 5% |
| 输出 `evidence` 包含数字的占比 | > 95% | < 90% |

> 关键指标异常先在告警(ES + Grafana)做,**暂未在当前基线中**(留作未来工作)。

---

## 9. 改 / 加 / 删 流程

### 9.1 新增行为(BEH-xxx)
1. 在 `beh-rules.yaml` 添加规则,生成新 `id: BEH-XXX`
2. 评估严重度表(system.md 表格)是否需要补列;按需更新
3. 在 `skills/` 新建 `<attack_class>.md`,frontmatter triggers 包含新 BEH id
4. 在 output.md 枚举 verdict 命名(`<attack_class>_suspected`)加入
5. 跑静态检查 + 1-2 个 sample unit 验证 SkillLoader 路由命中

### 9.2 新增工具
1. 在 `tools.py` + `registry.py` 实现 + 注册
2. system.md 不必改(工具目录自动注入)
3. 现有 skill 的 `mcp_tools` 列表按需更新

### 9.3 升级 verdict 字段(慎之又慎)
1. **先**改 `schemas/verdict.py` + 现有节点 + 现有所有 consumer
2. **再**改 `output.md` schema + few-shot
3. **再**改 `nodes.py` parse 逻辑
4. 跑回归:确保旧数据不被新代码读坏(Verdict 缺字段时设默认)

### 9.4 修改严重度阈值
- 只改 `system.md` 表格(数字 + 条件)
- 不改 output.md 与 skill 阈值(每个 skill 的"判定阈值"更具体)
- 改完跑 §8.1 静态 + §8.2 动态 1 周观测

### 9.5 删除 / 下线
- skill:删除 `.md` 文件,跑 SkillLoader 测试(路由命中数变化)
- 规则:删除 `beh-rules.yaml` 条目,跑 RuleEngine 测试;若 verdict 命名变化同步改 output.md 枚举
- 工具:删除 `tools.py` 注册;跑 MCP 工具列表断言;所有 skill 引用去除该工具

---

## 10. 常见陷阱(QA checklist)

| 陷阱 | 表现 | 预防 |
|---|---|---|
| 思考模式未关 | 384 token 全空,JSON 解析失败 | system.md 强提示"不要思考,直接给 JSON";server 启动参数 `--chat-template-kwargs {"enable_thinking":false}` |
| verdict 写中文 | 后续指纹/合并/检索失效 | output.md few-shot 全部英文,枚举清单 |
| evidence 空话("发现可疑活动") | 误报高、人审无用 | system.md 表格 + 每次 review 抽查 |
| iocs 字段被编造(幻觉) | 误报 / 错告警 | 反幻觉条款 + few-shot 强调"只填摘要里出现过的" |
| 工具被无限循环调用 | 延迟爆炸 / 资源耗尽 | system.md 明确"≤ 2 次" + 代码 max_tool_calls |
| tool 结果被复述进 verdict | 输出 token 爆 | truncate_result(256 token)+ system.md 强调"结果仅作为判断依据,不复述" |
| prompt 与 schema 不一致 | JSON 解析失败 | §8.1 静态校验 + review |
| `triggers.behavior` 与规则 id 不匹配 | skill 永远不被路由选中 | CI 静态断言 |
| skill 缺 few-shot | 小模型输出飘 | §9 改 / 加 / 删 流程强制要求 |
| 同 verdict 命名(中文 vs 英文)漂移 | 告警指纹去重失效 | output.md 枚举 + review |
| system.md 越改越长(> 2k token) | 超过 slot 容量,触发 LLM 截断 | 原则:system.md ≤ 1200 token,长内容放 skill |
| 修改 schema 忘改 output.md | 解析失败 | §7.1 同步发布流程 |

---

## 11. 变更与回滚

- **commit 范围**:prompt / skill / output.md 三件套 + 关联 rules/schemas/tools 改动应在同一次 PR
- **回滚手段**:git revert commit;若 schema 改动已落 ES,需回填 default
- **A/B**:可临时用两版 skill 共存 + SkillLoader.route 增加 "version" 字段打分
- **影子跑法**:用 mirror 流量在灰度节点跑新 prompt,主流量不变

---

## 12. 与代码的映射表(参考)

| Prompt 元素 | 物理位置 | 说明 |
|---|---|---|
| `{asset_context}` | `AssetKB.context_for()` | src/dst IP 资产摘要 |
| `{tool_directory}` | `ToolRegistry.directory()` | 工具名+一句话描述列表 |
| `{skill}` | `SkillLoader.load_for(behavior_ids, proto)` | 路由命中 1-2 个 skill 全文 |
| `{task_json}` | `AnalysisUnit.model_dump_json()` | 单元 JSON 摘要 |
| output schema 权威 | `src/agent/app/schemas/verdict.py` (`Verdict`) | prompt 渲染的 schema 必须与之一致 |
| 工具注册 | `src/agent/app/mcp/tools.py` + `registry.py` | tool 名称必须与 `mcp_tools` 中字符串一致 |
| Skill frontmatter 解析 | `src/agent/app/skills/loader.py` | 字段含义见 §5.1 |
| 路由评分 | `SkillLoader.route()` | §5.2 |
| Skill 裁断 | `Skill.activation_text()` | 按 `context_budget*4` 字符截断 |
| Skill 触发 | `nodes._process_session` → `SkillLoader.load_for()` | behavior 从 `engine.evaluate()` 拿,proto 从 `ev.proto` |
| 模型调用 | `nodes.model()` | `gateway.generate(provider, messages, tools=…, response_schema=verdict_schema())` |

---

## 13. 未来增强(留作后续)

- **多模型路由**:`small` (Qwen3-0.6B) 处理常规会话,`large` (Qwen3-32B) 处理 escalate;在 `escalate_check` 决定而非 system.md 提
- **多模态**:Zeek 文件(`zeek.files`)有样本,模型可读 magic/filename 给 ATT&CK 标注
- **Skill A/B**:SkillLoader 支持多版本并存
- **领域微调**:产出 SFT 数据集(verdict + evidence 复审)→ 训练更小模型
- **测试用例**:`src/agent/tests/test_prompts.py` + SkillLoader 路由单测
- **观测**:把 §8.2 指标接到现有 `Metrics` 框架(可注入 Prometheus 抓点)
- **PROMPT 评分**:用 LLM-as-judge 自动评估一批样本 verdict 的合理性

---

## 14. 附录:基线清单(2026-09 快照)

| 文件 | 行数 | 版本 |
|---|---|---|
| `src/agent/prompts/system.md` | 58 | 1.0 |
| `src/agent/prompts/task.md` | 30 | 1.0 |
| `src/agent/prompts/output.md` | 73 | 1.0 |
| `src/agent/skills/smb-lateral-movement.md` | 28 | 1.0 |
| `src/agent/skills/dns-tunneling.md` | 26 | 1.0 |
| `src/agent/skills/web-login-bruteforce.md` | 24 | 1.0 |
| `src/agent/skills/data-exfiltration.md` | 25 | 1.0 |
| `src/agent/skills/port-scan.md` | 24 | 1.0 |
| `src/agent/skills/ssh-bruteforce.md` | 28 | 1.0 |
| `src/agent/skills/web-exploit-attempt.md` | 24 | 1.0 |
| `src/agent/skills/anomalous-outbound.md` | 25 | 1.0 |
| `src/agent/skills/credential-theft.md` | 24 | 1.0 |
| `src/agent/skills/privilege-escalation.md` | 24 | 1.0 |
| `src/agent/skills/rdp-bruteforce.md` | 24 | 1.0 |
| `src/agent/skills/low-signal-baseline.md` | 23 | 1.0 |
| `src/agent/skills/dns-tunnel.md` | 29 | 1.0(待下线,与 dns-tunneling 重叠) |

> 这份设计文档与 `system.md` / `output.md` / skills 的内容是**双轨演进**的:本文档讲"为什么/怎么改",prompt 文件讲"改什么"。修任何 prompt 时,两份要一起 review。
