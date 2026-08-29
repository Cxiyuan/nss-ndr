"""结论（设计文档 §13.3）：写 Redis 缓存 + 双写 ES 历史索引。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Verdict(BaseModel):
    risk_level: str = "low"
    verdict: str = "benign"
    evidence: str = ""
    iocs: list[dict] = Field(default_factory=list)
    suggest_action: str = ""
    model: str = ""
    ver: int = 1
    watermark: dict = Field(default_factory=dict)
    trace_id: str = ""
    created_at: str = ""
    behavior_hits: list[str] = Field(default_factory=list)
    truncated: bool = False

    def is_same(self) -> bool:
        return self.verdict == "same"

    def is_uncertain(self) -> bool:
        return self.verdict in ("uncertain", "error")
