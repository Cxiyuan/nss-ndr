"""analysis_unit（设计文档 §13.2）：规则引擎输出，模型输入。"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class AggregationLevel(str, Enum):
    SESSION = "session"
    FLOW = "flow"
    HOST = "host"


class BehaviorHit(BaseModel):
    behavior_id: str
    name: str
    attck: str
    initial_risk: str
    count: int
    matched: bool


class AnalysisUnit(BaseModel):
    """规则引擎输出：聚合摘要 + 命中行为 + 升级标志 + watermark。"""

    session_key: str = Field(..., description="sess:{src}:{dst}:{dst_port}:{proto}")
    aggregation_level: AggregationLevel = AggregationLevel.SESSION
    window_seconds: int = 300
    events: list[str] = Field(default_factory=list, description="事件 event_id 列表")
    event_count: int = 0
    summary: dict = Field(default_factory=dict, description="三层聚合摘要（压缩后）")
    behavior_hits: list[BehaviorHit] = Field(default_factory=list)
    initial_risk: str = "low"
    estimated_tool_calls: int = 0
    requires_chain_analysis: bool = False
    rule_resolved: bool = False
    watermark: dict = Field(default_factory=dict, description="last_event_id/last_ts/event_count")
    # 基线/异常检测（设计文档 §14）：与 analysis_unit 合并
    anomaly_score: float = 0.0
    anomaly_confidence: float = 0.0
    anomaly_dimensions: list[str] = Field(default_factory=list)
    anomaly_phase: str = ""
    anomaly_alert: bool = False

    @property
    def risk_level(self) -> str:
        return self.initial_risk

    @property
    def behavior_hit_ids(self) -> list[str]:
        return [b.behavior_id for b in self.behavior_hits if b.matched]
