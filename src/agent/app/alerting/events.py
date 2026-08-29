"""告警与事件闭环（设计文档 §11）：指纹去重 + 状态机 + 通知。"""

from __future__ import annotations

import time

import httpx

from app.schemas.verdict import Verdict
from app.storage.es_store import ESStore
from app.storage.redis_store import timestamp_now


class AlertStore:
    def __init__(self, es: ESStore, webhook_url: str | None = None, dry_run: bool = False):
        self.es = es
        self.webhook_url = webhook_url
        self.dry_run = dry_run
        self._seen: dict[str, str] = {}  # fingerprint -> status

    async def handle(self, fingerprint: str, sess: str, verdict: Verdict, trace_id: str) -> dict:
        status = self._seen.get(fingerprint, "open")
        # 状态机：open → triage → confirmed/in_progress → closed / false_positive
        if verdict.risk_level == "low":
            status = "closed"  # 低风险只记录
        elif verdict.risk_level in ("medium", "high"):
            status = "open" if status not in ("open", "triage", "confirmed", "in_progress") else status
        self._seen[fingerprint] = status
        alert_doc = {
            "fingerprint": fingerprint,
            "sess": sess,
            "status": status,
            "risk_level": verdict.risk_level,
            "verdict": verdict.verdict,
            "behavior_hits": verdict.behavior_hits,
            "evidence": verdict.evidence[:500],
            "trace_id": trace_id,
            "@timestamp": timestamp_now(),
        }
        if not self.dry_run:
            await self.es.write_doc(self.es.alert_index, alert_doc)
            if self.webhook_url:
                await self._notify(alert_doc)
        return alert_doc

    async def _notify(self, alert: dict) -> None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self.webhook_url, json=alert)
        except Exception:  # noqa: BLE001
            pass  # 通知失败不阻断主链路
