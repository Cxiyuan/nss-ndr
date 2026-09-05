# 输出格式(强约束)
> Version: 2.0 · 2026-09-04
**只输出一个 JSON 对象**,无任何前后缀 / 注释 / Markdown 代码块。

## Schema(逐字段)
```jsonc
{
  "risk_level": "low|medium|high",                  // 必填
  "verdict": "<attack_class>_suspected|benign|uncertain|same", // 必填
  "evidence": "引用本会话 features/工具结果真实值,含至少 1 个数字", // 必填
  "iocs": [{"type": "ip|domain|url|hash|...", "value": "..."}], // 必填,无则 []
  "suggest_action": "可执行处置建议"                  // 必填,无则 ""
}
```
- verdict 攻击类示例:`smb_bruteforce_suspected / ssh_bruteforce_suspected / rdp_bruteforce_suspected /
  web_login_bruteforce_suspected / dns_tunnel_suspected / data_exfiltration_suspected /
  web_exploit_attempt_suspected / port_scan_suspected / lateral_movement_suspected /
  credential_theft_suspected / privilege_escalation_suspected / anomalous_outbound_suspected`
- `iocs[].type` 枚举:ip|domain|url|hash|email|filepath|user|md5|sha256|ja3|sni|asn|cve…

## 关键规则
1. evidence 必须与 **summary.features / es_search 结果** 里的实际值一致;禁止使用下方示例中的数值冒充本会话数据。
2. features 缺失关键细节且工具取不到 → `verdict:"uncertain"`,evidence 写明缺什么。
3. 下列示例**仅为格式演示,禁止逐字复用**(示例 IP/次数/字段值都不可照抄)。

## 格式示例(勿照抄数值)
```json
{
  "risk_level": "medium",
  "verdict": "smb_bruteforce_suspected",
  "evidence": "引用本会话 BEH-xxx/features 的真实字段与数值(命中规则时以 BEH-xxx 窗口统计为第一依据)",
  "iocs": [],
  "suggest_action": "按本会话真实情况给出可执行处置(不得照抄示例)"
}
```

## 反例(禁止)
- ❌ `以下是判定: {...}`
- ❌ ```json ... ``` 代码块
- ❌ 多余文字 / 解释
- ❌ 缺失字段(不要用 null 占位)
- ❌ verdict 用中文
- ❌ evidence 空话("发现可疑活动")或无数字
- ❌ 直接复制示例内容(字段值、IP、次数)
