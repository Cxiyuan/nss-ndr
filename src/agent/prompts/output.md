输出约束：仅输出一个 JSON 对象，不要任何额外文字或 Markdown 代码块标记。字段：
{
  "risk_level": "low|medium|high",
  "verdict": "字符串结论（如 smb_bruteforce_suspected）",
  "evidence": "关键证据摘要（时间/行为/计数）",
  "iocs": [{"type": "domain|ip|url", "value": "..."}],
  "suggest_action": "处置建议"
}
