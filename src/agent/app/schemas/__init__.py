"""统一数据契约（设计文档第十三章）。"""

from .analysis import AggregationLevel, AnalysisUnit, BehaviorHit
from .event import EventEnvelope
from .keys import (
    agent_chain_key,
    agent_entity_key,
    agent_result_key,
    alert_fingerprint,
    evt_key,
    lock_key,
    normalize_ip,
    session_key,
)
from .verdict import Verdict

__all__ = [
    "AggregationLevel",
    "AnalysisUnit",
    "BehaviorHit",
    "EventEnvelope",
    "Verdict",
    "normalize_ip",
    "session_key",
    "evt_key",
    "lock_key",
    "alert_fingerprint",
    "agent_result_key",
    "agent_entity_key",
    "agent_chain_key",
]
