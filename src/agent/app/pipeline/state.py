"""AgentState（设计文档 §9.2）：图内共享状态。"""

from __future__ import annotations

from typing import TypedDict

from app.schemas.analysis import AnalysisUnit
from app.schemas.event import EventEnvelope
from app.schemas.verdict import Verdict


class AgentState(TypedDict, total=False):
    session_key: str
    events: list[EventEnvelope]
    unit: AnalysisUnit
    cached: Verdict | None
    local: Verdict | None
    final: Verdict | None
    provider: str
    messages: list[dict]
    tool_calls_made: int
    trace_id: str
    acked: bool
    reused: bool
    escalated: bool
    asset_context: str
    skill: str
