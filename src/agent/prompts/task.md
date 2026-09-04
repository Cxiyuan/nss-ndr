# 分析任务
对下列 **AnalysisUnit(同一会话聚合单元)** 给出最终安全判定。
会话按 `(src_ip, dst_ip, dst_port, proto)` 四元组聚合,窗口内多事件压缩为统一摘要。

## 输入字段说明
| 字段 | 含义 | 用途 |
|---|---|---|
| `session_key` | 会话唯一标识 `sess:{src}:{dst}:{port}:{proto}` | 检索缓存/去重 |
| `aggregation_level` | SESSION / FLOW / HOST | 当前都按 SESSION 处理 |
| `window_seconds` | 聚合时间窗(秒) | 用于判定"短时间内" |
| `event_count` | 本案事件条数 | 强度指标 |
| `summary` | 规则引擎三层压缩摘要(services / durations / bytes / queries / status_codes / top_talkers 等) | 你的主要数据源 |
| `behavior_hits` | 已命中的规则清单(`behavior_id` / `name` / `attck` / `initial_risk` / `count`) | 必须**基于这些继续研判**,不要忽略 |
| `initial_risk` | low / medium / high(由规则初判) | 你的起点 |
| `rule_resolved` | true 表示规则已能直接下结论,你要做的是确认 / 微调 / 给证据,不必做更多研判 |  |
| `estimated_tool_calls` | 建议调用的工具数(0/1/2) | 别超过这个数 |
| `requires_chain_analysis` | true 表示需要跨 IP 时序分析 → 调 `detect_chain_sequence` |  |
| `anomaly_*` | 基线异常评分/置信/维度/告警 | 综合判定风险等级的强信号 |
| `events[ids]` | 关联的原始事件 ID 列表(你读不到原始 Zeek 字段,需用 `es_search` 工具) |  |

## 你要做的事
1. 读 `behavior_hits` 与 `summary` → 理解这案在做什么
2. 如果 `initial_risk=high` 或 `requires_chain_analysis=true` 或 `estimated_tool_calls>=1` → 考虑调工具补充信息
3. 综合规则命中 + 基线异常 + 工具结果 → 给出最终 verdict / risk_level / evidence / iocs / suggest_action

## 注意
- 本会话内已有 1 小时内的缓存 verdict → 你可能收到 `reused=true` 的同单元,**不要重复推理**,直接复用结果
- 不要去查**无关的**行为或资产,聚焦本会话四元组
- `summary` 中各字段缺失表示规则未聚合到,不是"零"
- 同一会话有 `multiple events` 时,evidence 里要给出**时间窗 + 速率**而非只给累计
