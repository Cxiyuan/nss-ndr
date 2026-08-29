"""资产知识库（设计文档 §10）：v1 CSV 种子 + 内存检索；ES 档案索引为部署期导入。"""

from __future__ import annotations

import csv
from pathlib import Path


class AssetKB:
    def __init__(self, seed_file: str | Path = "data/assets.example.csv"):
        self.records: dict[str, dict] = {}
        path = Path(seed_file)
        if path.exists():
            with path.open(encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    ip = (row.get("ip") or "").strip()
                    if ip:
                        self.records[ip] = row

    def lookup(self, ip: str) -> dict | None:
        return self.records.get(ip)

    def context_for(self, ips: list[str], top_n: int = 3) -> str:
        """资产上下文按需检索：仅注入涉及 IP 的 Top-N 档案（设计文档 §4.1 RAG）。"""
        lines = []
        for ip in ips[:top_n]:
            rec = self.lookup(ip)
            if rec:
                lines.append(
                    f"资产 {ip}: 业务={rec.get('business', '未知')}, 端口={rec.get('ports', '')}, "
                    f"负责人={rec.get('owner', '')}, 重要性={rec.get('importance', '')}, 已知漏洞={rec.get('known_vulns', '无')}"
                )
        return "\n".join(lines)
