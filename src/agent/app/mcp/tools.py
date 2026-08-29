"""MCP 工具实现（设计文档 §5.3 关联查询工具集 + §6）。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.mcp.registry import ToolRegistry, ToolSpec

if TYPE_CHECKING:
    from app.storage.es_store import ESStore
    from app.storage.redis_store import RedisStore


def _ip_param(desc: str = "IP 地址") -> dict:
    return {"type": "string", "description": desc}


def _time_range_param() -> dict:
    return {
        "type": "string",
        "description": "ISO8601 时间范围，如 1h / 24h / 2026-08-29T00:00:00Z,2026-08-29T01:00:00Z",
        "default": "1h",
    }


def build_tools(es: "ESStore", redis: "RedisStore") -> ToolRegistry:
    registry = ToolRegistry()

    async def es_search(index: str, query_dsl: dict, time_range: str = "1h", size: int = 20) -> dict:
        """ES 聚合/检索兜底工具（时间回溯策略第③级）。"""
        if es.client is None:
            return {"error": "ES 未连接", "hits": []}
        body = {"query": query_dsl, "size": size}
        resp = await es.client.search(index=index, body=body)
        return {"total": resp.get("hits", {}).get("total", {}).get("value", 0), "hits": resp["hits"]["hits"][:size]}

    async def query_peer_relations(ip: str, time_range: str = "1h", direction: str = "both") -> dict:
        """该 IP 的对端关系列表（IP/连接次数/首末时间）。"""
        hours = _hours(time_range)
        details = await es.fetch_details(ip, "*", _since(hours))
        peers: dict[str, dict] = {}
        for d in details:
            src, dst = d.get("source", {}).get("ip"), d.get("destination", {}).get("ip")
            peer = dst if src == ip else src
            if not peer:
                continue
            if direction == "out" and src != ip:
                continue
            if direction == "in" and dst != ip:
                continue
            entry = peers.setdefault(peer, {"peer": peer, "count": 0, "first": d.get("@timestamp", ""), "last": d.get("@timestamp", "")})
            entry["count"] += 1
            if d.get("@timestamp", "") < entry["first"]:
                entry["first"] = d["@timestamp"]
            if d.get("@timestamp", "") > entry["last"]:
                entry["last"] = d["@timestamp"]
        return {"ip": ip, "direction": direction, "peers": sorted(peers.values(), key=lambda x: -x["count"])[:50]}

    async def count_behavior_hits(ip: str, behavior_ids: list[str], time_range: str = "1h") -> dict:
        """指定 IP 在时间内命中各行为编号的计数（来自历史结论索引）。"""
        verdicts = await es.search_verdicts(ip, _hours(time_range))
        counts: dict[str, int] = {}
        for v in verdicts:
            for bid in v.get("behavior_hits", []):
                if bid in behavior_ids:
                    counts[bid] = counts.get(bid, 0) + 1
        return {"ip": ip, "counts": counts}

    async def detect_chain_sequence(ips: list[str], behavior_chain: list[str], time_range: str = "24h") -> dict:
        """按给定行为链顺序检测多 IP 间是否存在时序链（0/1 及命中路径）。"""
        if len(ips) < 2 or len(behavior_chain) < 2:
            return {"found": 0, "path": []}
        events_by_ip: dict[str, list[str]] = {}
        for ip in ips:
            verdicts = await es.search_verdicts(ip, _hours(time_range))
            for v in verdicts:
                if any(b in behavior_chain for b in v.get("behavior_hits", [])):
                    events_by_ip.setdefault(ip, []).append(v.get("@timestamp", ""))
        ordered = [ip for ip in ips if events_by_ip.get(ip)]
        timestamps = [min(events_by_ip[ip]) for ip in ordered]
        if len(ordered) >= 2 and all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1)):
            return {"found": 1, "path": list(zip(ordered, behavior_chain[: len(ordered)]))}
        return {"found": 0, "path": []}

    async def get_entity_profile(ip: str, top_n: int = 10) -> dict:
        """该 IP 的实体画像摘要（Redis 滚动窗口，设计文档 §4.2）。"""
        profile = await redis.get_entity(ip)
        return {"ip": ip, "profile": profile[-top_n:]}

    registry.register(
        ToolSpec(
            name="es_search",
            description="在 Elasticsearch 中执行聚合查询，返回统计结果",
            parameters={
                "type": "object",
                "properties": {
                    "index": {"type": "string", "description": "索引或通配符"},
                    "query_dsl": {"type": "object", "description": "ES Query DSL"},
                    "time_range": _time_range_param(),
                    "size": {"type": "integer", "default": 20},
                },
                "required": ["index", "query_dsl"],
            },
            handler=es_search,
            group="network",
        )
    )
    registry.register(
        ToolSpec(
            name="query_peer_relations",
            description="查询指定IP的对端关系，返回对端IP列表及连接次数",
            parameters={
                "type": "object",
                "properties": {
                    "ip": _ip_param(),
                    "time_range": _time_range_param(),
                    "direction": {"type": "string", "enum": ["both", "in", "out"], "default": "both"},
                },
                "required": ["ip"],
            },
            handler=query_peer_relations,
            group="network",
        )
    )
    registry.register(
        ToolSpec(
            name="count_behavior_hits",
            description="统计指定IP在时间范围内命中某行为编号的次数",
            parameters={
                "type": "object",
                "properties": {
                    "ip": _ip_param(),
                    "behavior_ids": {"type": "array", "items": {"type": "string"}},
                    "time_range": _time_range_param(),
                },
                "required": ["ip", "behavior_ids"],
            },
            handler=count_behavior_hits,
            group="network",
        )
    )
    registry.register(
        ToolSpec(
            name="detect_chain_sequence",
            description="检测多个IP之间是否存在时序行为链",
            parameters={
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "behavior_chain": {"type": "array", "items": {"type": "string"}},
                    "time_range": _time_range_param(),
                },
                "required": ["ips", "behavior_chain"],
            },
            handler=detect_chain_sequence,
            group="network",
        )
    )
    registry.register(
        ToolSpec(
            name="get_entity_profile",
            description="获取指定IP的实体画像摘要",
            parameters={
                "type": "object",
                "properties": {"ip": _ip_param(), "top_n": {"type": "integer", "default": 10}},
                "required": ["ip"],
            },
            handler=get_entity_profile,
            group="network",
        )
    )
    return registry


def _hours(time_range: str) -> int:
    if time_range.endswith("h"):
        return max(1, int(time_range[:-1]))
    if time_range.endswith("m"):
        return max(1, int(time_range[:-1]) // 60)
    if time_range.endswith("d"):
        return int(time_range[:-1]) * 24
    return 1


def _since(hours: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
