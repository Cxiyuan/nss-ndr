"""事件信封（设计文档 §13.1）：Logstash 双写进 Redis Stream 的最小事件。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EventEnvelope(BaseModel):
    """事件信封：event_id / @timestamp / 五元组 / proto / 富化标签 / trace_id。"""

    event_id: str = Field(..., description="幂等去重 ID")
    ts: str = Field(..., description="事件时间戳")
    src_ip: str = Field(..., description="源 IP")
    src_port: str = Field("", description="源端口")
    dst_ip: str = Field(..., description="目标 IP")
    dst_port: str = Field("", description="目标端口")
    proto: str = Field("", description="传输协议 tcp/udp/icmp")
    dataset: str = Field("zeek.connection", description="Zeek 数据流类型")
    enriched: dict = Field(default_factory=dict, description="富化标签（IOC 命中等）")
    trace_id: str = Field("", description="链路追踪 ID")

    @property
    def five_tuple(self) -> tuple[str, str, str, str, str]:
        return (
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.proto,
        )


def event_from_stream(fields: dict) -> EventEnvelope:
    """把 Redis Stream 条目字段解析为 EventEnvelope。"""
    return EventEnvelope(
        event_id=fields.get("event_id", ""),
        ts=fields.get("ts", ""),
        src_ip=fields.get("src_ip", ""),
        src_port=fields.get("src_port", "") or "",
        dst_ip=fields.get("dst_ip", ""),
        dst_port=fields.get("dst_port", "") or "",
        proto=fields.get("proto", "") or "",
        dataset=fields.get("dataset", "zeek.connection") or "zeek.connection",
        enriched={"labels": fields.get("labels", [])} if fields.get("labels") else {},
    )
