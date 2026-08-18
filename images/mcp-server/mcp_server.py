#!/usr/bin/env python3
"""NSS-NDR MCP Server：向本地 Agent 暴露分析工具集。

工具实现直接查询探针本地 ES（logs-zeek-so / logs-suricata.alerts-so / logs-strelka-so），
数据不出设备；Agent 通过 MCP 协议（streamable HTTP）调用这些工具完成关联分析。
"""
import os
from datetime import datetime, timedelta, timezone
from mcp.server.fastmcp import FastMCP
from elasticsearch import Elasticsearch

ES_HOST = os.getenv("ES_HOST", "http://nss-elasticsearch:9200")
ES_USER = os.getenv("ES_USERNAME", "xdr-push")
ES_PASS = os.getenv("ES_PASSWORD", "")
MAX_EVENTS = int(os.getenv("MCP_MAX_EVENTS", "200"))

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS) if ES_PASS else None,
                   request_timeout=30, verify_certs=False)

mcp = FastMCP("ndr-analysis")

DATASETS = {
    "conn": "zeek.conn", "dns": "zeek.dns", "http": "zeek.http",
    "ssl": "zeek.ssl", "tls": "zeek.ssl", "smb": "zeek.smb_files",
    "smb_files": "zeek.smb_files", "smb_mapping": "zeek.smb_mapping",
    "ntlm": "zeek.ntlm", "files": "zeek.files", "ssh": "zeek.ssh",
}


def _time_range(window_seconds: int) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now - timedelta(seconds=max(window_seconds, 1)), now


def _target_filter(target: dict) -> list[dict]:
    filters = []
    for field, key in (("community_id", "network.community_id"),
                       ("src_ip", "source.ip"),
                       ("dst_ip", "destination.ip"),
                       ("uid", "log.id.uid")):
        if target.get(field):
            filters.append({"term": {key: target[field]}})
    return filters


def _summary(src: dict) -> dict:
    """提取元数据事件关键字段（对齐 ndr-manager summarizeTaskEvent）"""
    get = lambda *ks: _dig(src, *ks)
    out = {
        "@timestamp": get("@timestamp"),
        "event.dataset": get("event", "dataset"),
        "source.ip": get("source", "ip"),
        "source.port": get("source", "port"),
        "destination.ip": get("destination", "ip"),
        "destination.port": get("destination", "port"),
        "network.transport": get("network", "transport"),
        "network.community_id": get("network", "community_id"),
    }
    for path, keys in {
        "dns.question.name": ("dns", "question", "name"),
        "dns.question.type": ("dns", "question", "type"),
        "dns.response_code": ("dns", "response_code"),
        "dns.answers": ("dns", "answers"),
        "url.full": ("url", "full"),
        "http.request.method": ("http", "request", "method"),
        "http.response.status_code": ("http", "response", "status_code"),
        "user_agent.original": ("user_agent", "original"),
        "tls.server.name": ("tls", "server", "name"),
        "tls.ja3": ("tls", "ja3"),
        "smb.action": ("smb", "action"),
        "smb.path": ("smb", "path"),
        "smb.name": ("smb", "name"),
        "smb.share_type": ("smb", "share_type"),
        "ntlm.username": ("ntlm", "username"),
        "file.mime_type": ("file", "mime_type"),
        "file.name": ("file", "name"),
        "connection.state": ("connection", "state"),
        "event.duration": ("event", "duration"),
    }.items():
        v = _dig(src, *keys)
        if v is not None:
            out[path] = v
    return out


def _dig(src: dict, *keys):
    cur = src
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _search_events(index: str, filters: list[dict], size: int = MAX_EVENTS) -> list[dict]:
    body = {
        "size": size,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": "asc"}],
    }
    resp = es.search(index=index, body=body)
    return [_summary(h["_source"]) for h in resp["hits"]["hits"]]


@mcp.tool()
def list_datasets() -> dict:
    """列出探针本地可分析的元数据集目录（供 Agent 了解 NDR 有哪些数据源）。"""
    return {"datasets": [{"name": k, "event.dataset": v} for k, v in DATASETS.items()],
            "indexes": ["logs-zeek-so", "logs-suricata.alerts-so", "logs-strelka-so"]}


@mcp.tool()
def query_metadata(target: dict, datasets: list[str] | None = None,
                   window_seconds: int = 3600, conditions: dict | None = None,
                   size: int | None = None) -> dict:
    """按目标（community_id/src_ip/dst_ip/uid）与时间窗检索指定数据集的元数据事件。

    Args:
        target: {"community_id": "...", "src_ip": "...", "dst_ip": "...", "uid": "..."} 至少一项
        datasets: 数据集列表（conn/dns/http/ssl/smb_files/smb_mapping/ntlm/files/ssh），默认全查
        window_seconds: 回溯窗口（秒），默认 3600
        conditions: 附加 term 条件，如 {"http.response.status_code": 200}
        size: 单数据集最大返回事件数（默认 MCP_MAX_EVENTS=200，上限 1000）
    """
    if not target or not any(target.values()):
        return {"error": "target 至少需要 community_id/src_ip/dst_ip/uid 之一"}
    ds_list = datasets or list(DATASETS.keys())
    start, end = _time_range(window_seconds)
    sz = min(size or MAX_EVENTS, 1000)
    result = {"window_seconds": window_seconds, "from": start.isoformat(), "to": end.isoformat(),
              "target": target, "datasets": {}}
    for ds in ds_list:
        es_ds = DATASETS.get(str(ds).lower())
        if not es_ds:
            continue
        filters = [{"term": {"event.dataset": es_ds}},
                   {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
        filters += _target_filter(target)
        for k, v in (conditions or {}).items():
            filters.append({"term": {k: v}})
        try:
            events = _search_events("logs-zeek-so", filters, size=sz)
        except Exception as e:  # 数据集可能尚无数据
            events = []
        result["datasets"][ds] = {"count": len(events), "events": events}
    result["total"] = sum(v["count"] for v in result["datasets"].values())
    return result


@mcp.tool()
def correlate_session(community_id: str, window_seconds: int = 3600) -> dict:
    """按 community_id 拉取某会话全链路元数据（conn/dns/http/ssl/smb_files/smb_mapping/ntlm/files）。"""
    return query_metadata({"community_id": community_id},
                          ["conn", "dns", "http", "ssl", "smb_files", "smb_mapping", "ntlm", "files"],
                          window_seconds)


@mcp.tool()
def aggregate_stats(target: dict, window_seconds: int = 3600,
                    field: str = "destination.port", top_n: int = 10) -> dict:
    """对某目标/时间窗的元数据做统计聚合（默认按目的端口 topN）。

    Args:
        target: 目标定位（community_id/src_ip/dst_ip/uid）
        window_seconds: 回溯窗口（秒）
        field: 聚合字段，如 destination.port / server.domain / user_agent.original / dns.question.name
        top_n: 返回条数
    """
    start, end = _time_range(window_seconds)
    filters = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
    filters += _target_filter(target)
    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {"top": {"terms": {"field": field, "size": top_n}}},
    }
    resp = es.search(index="logs-zeek-so", body=body)
    buckets = resp["aggregations"]["top"]["buckets"]
    return {"field": field, "window_seconds": window_seconds, "target": target,
            "top": [{"key": b["key"], "count": b["doc_count"]} for b in buckets]}


@mcp.tool()
def get_clue(target: dict, window_seconds: int = 3600) -> dict:
    """检索检测线索（Suricata 告警）：按源/目的 IP 或 community_id 返回线索事件。"""
    start, end = _time_range(window_seconds)
    filters = [{"term": {"event.dataset": "suricata.alert"}},
               {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
    filters += _target_filter(target)
    events = _search_events("logs-suricata.alerts-so", filters)
    return {"target": target, "window_seconds": window_seconds, "count": len(events), "clues": events}


@mcp.tool()
def query_files(mime_type: str | None = None, md5: str | None = None,
                window_seconds: int = 3600, size: int = 50) -> dict:
    """查询文件分析结果（Strelka）：按 MIME 类型或 MD5 检索，返回文件元数据与判定。"""
    start, end = _time_range(window_seconds)
    filters = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
    if mime_type:
        filters.append({"term": {"file.mime_type": mime_type}})
    if md5:
        filters.append({"term": {"file.hash.md5": md5}})
    body = {"size": min(size, 200), "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": "desc"}]}
    try:
        resp = es.search(index="logs-strelka-so", body=body)
    except Exception:
        resp = {"hits": {"hits": []}}
    events = [h["_source"] for h in resp["hits"]["hits"]]
    return {"count": len(events), "files": events}


if __name__ == "__main__":
    # streamable HTTP 传输：Agent 通过 http://nss-mcp-server:8000/mcp 远程调用
    mcp.run(transport="streamable-http")
