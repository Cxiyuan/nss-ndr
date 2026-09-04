"""事件信封(设计文档 §13.1):Logstash 双写进 Redis Stream 的最小事件。"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field


# 协议推断:有些 zeek 数据流(dataset)本身不包含 L4 协议字段(ssl/http 是应用层)
# 落到 event.proto 为空串,导致按 (src,dst,port,proto) 分组时同端连接被拆成两组。
# 这里按 dataset 给出默认 L4 协议(原 proto 不为空时优先保留原值)
_PROTO_BY_DATASET_PREFIX: tuple[tuple[str, str], ...] = (
    ("zeek.ssl",   "tcp"),
    ("zeek.http",  "tcp"),
    ("zeek.https",  "tcp"),
    ("zeek.dns",   "udp"),
    ("zeek.dhcp",  "udp"),
    ("zeek.ntp",   "udp"),
    ("zeek.snmp",  "udp"),
    ("zeek.syslog","udp"),
    ("zeek.icmp",  "icmp"),
)


def _infer_proto(raw_proto: str, dataset: str) -> str:
    """协议推断:原值非空则优先,否则按 dataset 前缀补默认 L4 协议。"""
    if raw_proto:
        return raw_proto
    ds = (dataset or "").lower()
    for prefix, proto in _PROTO_BY_DATASET_PREFIX:
        if ds.startswith(prefix):
            return proto
    return ""


class EventEnvelope(BaseModel):
    """事件信封:event_id / @timestamp / 五元组 / proto / 富化标签 / trace_id。"""

    event_id: str = Field(..., description="幂等去重 ID")
    ts: str = Field(..., description="事件时间戳")
    src_ip: str = Field(..., description="源 IP")
    src_port: str = Field("", description="源端口")
    dst_ip: str = Field(..., description="目标 IP")
    dst_port: str = Field("", description="目标端口")
    # 修复#2:proto 在原值为空时按 dataset 推断默认 L4 协议
    proto: str = Field("", description="传输协议 tcp/udp/icmp(空时按 dataset 推断)")
    dataset: str = Field("zeek.connection", description="Zeek 数据流类型")
    # 修复#1:enriched 保留原 dict(labels 等)用于扩展,
    # 同时新增 enriched_flag:bool 反映"是否被上游富化过"
    enriched: dict = Field(default_factory=dict, description="富化标签(IOC 命中等)")
    enriched_flag: bool = Field(False, description="上游是否富化过(从 enriched=='true' 解析)")
    trace_id: str = Field("", description="链路追踪 ID")
    # Phase A: logstash 透传的 Zeek 信号字段(raw zeek 字段名,如 query/uri/conn_state)
    zeek: dict = Field(default_factory=dict, description="Zeek 原始高信号字段(透传,压缩用)")

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
    """把 Redis Stream 条目字段解析为 EventEnvelope。

    修复:
    - #1 enriched 字段:流里是字符串 "true" / "false" 或数组,统一解析为:
        enriched_flag(bool,上游是否富化过) + enriched(dict,标签等明细)
    - #2 proto 字段:流里 zeek.ssl/http/dns 等 L7 协议不携带 L4 字段,
        在原 proto 为空时按 dataset 推断默认 L4 协议
    - Phase A: 流里 "zeek" 字段(logstash JSON 序列化的信号字段)→ 解析为 dict,
        供规则引擎做 summary.features 压缩
    """
    raw_proto = (fields.get("proto") or "").strip()
    dataset = fields.get("dataset", "zeek.connection") or "zeek.connection"
    proto = _infer_proto(raw_proto, dataset)

    # enriched 解析:兼容多种上游写法
    raw_enriched = fields.get("enriched")
    enriched_flag = False
    enriched_dict: dict = {}
    if raw_enriched is True:
        enriched_flag = True
    elif isinstance(raw_enriched, str):
        enriched_flag = raw_enriched.strip().lower() in ("true", "1", "yes", "y")
        if enriched_flag:
            enriched_dict = {"_flag": True}
    elif isinstance(raw_enriched, dict):
        enriched_dict = dict(raw_enriched)
        # dict 内常见 marker:{"flag":true} / {"labels":[...]} / 直接 truthy
        if enriched_dict:
            v = enriched_dict.get("flag", enriched_dict)
            enriched_flag = bool(v) if not isinstance(v, (list, dict)) else True
    elif isinstance(raw_enriched, list):
        enriched_dict = {"labels": list(raw_enriched)}
        enriched_flag = bool(raw_enriched)

    # Phase A: zeek 信号字段(logstash 用 JSON 字符串,也可能直接是 dict)
    raw_zeek = fields.get("zeek")
    zeek_dict: dict = {}
    if isinstance(raw_zeek, dict):
        zeek_dict = dict(raw_zeek)
    elif isinstance(raw_zeek, str) and raw_zeek.strip():
        try:
            parsed = json.loads(raw_zeek)
            if isinstance(parsed, dict):
                zeek_dict = parsed
        except (json.JSONDecodeError, ValueError):
            zeek_dict = {}

    return EventEnvelope(
        event_id=fields.get("event_id", ""),
        ts=fields.get("ts", ""),
        src_ip=fields.get("src_ip", ""),
        src_port=fields.get("src_port", "") or "",
        dst_ip=fields.get("dst_ip", ""),
        dst_port=fields.get("dst_port", "") or "",
        proto=proto,
        dataset=dataset,
        enriched=enriched_dict,
        enriched_flag=enriched_flag,
        zeek=zeek_dict,
    )
