# 输出格式(强约束)
**只输出一个 JSON 对象**,不要任何额外文字、注释、Markdown 代码块。

## Schema(逐字段含义)
```jsonc
{
  // 必填
  "risk_level": "low" | "medium" | "high",

  // 必填
  // - 已知攻击类: "<attack_class>_suspected" 例:
  //   smb_bruteforce_suspected / ssh_bruteforce_suspected /
  //   rdp_bruteforce_suspected / web_login_bruteforce_suspected /
  //   dns_tunnel_suspected / anomalous_outbound_suspected /
  //   data_exfiltration_suspected / web_exploit_attempt_suspected /
  //   lateral_movement_suspected / credential_theft_suspected /
  //   privilege_escalation_suspected / port_scan_suspected
  // - 复用或无异常: "benign" | "same" | "uncertain"
  "verdict": "smb_bruteforce_suspected",

  // 必填。必须含**数字**(计数 / 阈值 / 时间窗 / 唯一实体数),不要写空话
  "evidence": "5min 内源 10.0.0.7 向 5 个 445 目标发起 47 次 SMB 连接,失败率 0.83",

  // 必填,缺失则填空 []
  "iocs": [
    {"type": "ip",   "value": "10.0.0.7"},
    {"type": "ip",   "value": "10.0.0.21"},
    {"type": "hash", "value": "<可选样本>"}
  ],

  // 必填,缺失填空字符串
  "suggest_action": "临时封禁源 IP 10.0.0.7,30 分钟后复盘并取证;转 SOC 高级工单"
}
```

## 类型字段枚举
- `iocs[].type`: `ip` | `domain` | `url` | `hash` | `email` | `filepath` | `user` | `md5` | `sha256` | `ja3` | `tls_fingerprint` | `sni` | `asn` | `cve` | 其他自描述
- 字段名严格小写 snake_case

## Few-shot 示例 1 — 中风险(SMB 爆破)
会话:10.0.0.7 → 10.0.0.21/445/tcp,5min 内 47 次连接、4 个目的 IP、conn_state 全 S0。
```json
{
  "risk_level": "medium",
  "verdict": "smb_bruteforce_suspected",
  "evidence": "5min 内源 10.0.0.7 向 4 个 445 目的发起 47 次 SMB 会话,失败率 0.83(conn_state=S0),无前期类似行为",
  "iocs": [{"type": "ip", "value": "10.0.0.7"}],
  "suggest_action": "在 10.0.0.21 网段 ACL 临时封禁源 10.0.0.7 24h;调取 10.0.0.7 近 1h 全量连接,确认账号爆破进展"
}
```

## Few-shot 示例 2 — 高风险(DNS 隧道 + 基线异常 + 历史命中)
会话:10.0.0.5 → 8.8.8.8/53/udp,300s 内 87 次 DNS 查询,query_name 熵值高、TXT 居多,且 anomaly_score=0.82 anomaly_alert=true。
```json
{
  "risk_level": "high",
  "verdict": "dns_tunnel_suspected",
  "evidence": "源 10.0.0.5 在 5min 内发起 87 次 DNS 查询,query_name 平均熵 4.1、长度 58,TXT 类型占 78%;异常分 0.82 高于基线;该 IP 历史 24h 内已有 3 次同类会话",
  "iocs": [
    {"type": "ip", "value": "10.0.0.5"},
    {"type": "domain", "value": "<query_name 示例>"}
  ],
  "suggest_action": "立即在内部 DNS 上阻断 10.0.0.5 的 53/tcp+udp 出向;抓包留存 10min;转云端复核 + 工单到 SOC"
}
```

## 反例(禁止)
- ❌ 字符串外加说明:`以下是判定: {...}`
- ❌ Markdown 代码块:` ```json ... ``` `
- ❌ 多余文字 / 解释 / 致谢
- ❌ 缺失字段(用 null 占位也不要)
- ❌ verdict 写成中文(必须英文 snake_case)
- ❌ evidence 写"发现可疑活动,建议关注"这种无数字空话
