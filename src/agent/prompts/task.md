# 分析任务
> Version: 2.0 · 2026-09-04
对下列 **AnalysisUnit(同一会话聚合单元)** 给出最终安全判定。
会话按 `<src>:<dst>:<port>:<proto>` 聚合,窗口内事件已压缩为摘要与特征。

## 输入字段
| 字段 | 含义 | 用途 |
|---|---|---|
| `session_key` | 会话唯一标识 | 检索/去重 |
| `window_seconds` | 聚合时间窗(秒) | 短时判定 |
| `event_count` | 本案总事件数 | 强度 |
| `summary.datasets` | 各 zeek 数据流计数(如 {{"zeek.dns":39}}) | 协议画像 |
| `summary.dst_ports` | 目的端口 | 服务画像 |
| `summary.features.zeek.dns` | top_queries / unique_domains / qtype_dist / avg_entropy | **DNS 研判依据** |
| `summary.features.zeek.connection` | services_dist / conn_states_dist / bytes_sum / duration_sum | **连接/流量研判依据** |
| `summary.features.zeek.http` | methods_dist / status_codes_dist / top_uris / hosts | **HTTP 研判依据** |
| `summary.features.zeek.ssl` | sni_set / ja3_cnt / cipher_set / validation_status | **TLS 研判依据** |
| `summary.features.zeek.files` | filenames / mime_dist | **文件研判依据** |
| `summary.features.zeek.notice` | msgs | **告警消息依据** |
| `behavior_hits` | 已命中规则(BEH-xxx/ATT&CK/count) | 必须复核,不要忽略 |
| `initial_risk` | 规则初判 low/medium/high | 你的起点 |
| `rule_resolved` | true=规则可直接判定,做确认/证据 | 避免过度推理 |
| `anomaly_*` | 基线异常分/维度/告警 | 强信号 |

> features 缺失某键 = 该数据流无透传特征,不代表正常;需要细节优先 es_search。

## 你要做的
1. 从 datasets + dst_ports + features 判断本会话"是什么流量"。
2. 用 behavior_hits 复核:特征是否支持该行为?rule_resolved=true 且支持 → 直接给结论。
3. 特征不足 → es_search(≤2 次)补细节。
4. 输出 JSON;evidence **必须引用本会话 features/工具结果中真实出现的字段与数值**,不得使用示例数值。

## 禁止
- 不编造任何 features/工具结果之外的 IP/域名/URI/端口/计数/字节。
- 不确定 → uncertain + 写明缺什么,禁止用 low 逃避。
- 不复读 output.md 示例内容。
- 不输出多余文字或代码块。
