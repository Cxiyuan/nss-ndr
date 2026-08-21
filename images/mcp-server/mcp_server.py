#!/usr/bin/env python3
"""NSS-NDR MCP Server：向本地 Agent 暴露分析工具集。

工具实现直接查询探针本地 ES（logs-zeek-so / logs-suricata.alerts-so / logs-strelka-so），
数据不出设备；Agent 通过 MCP 协议（streamable HTTP）调用这些工具完成关联分析。
"""
import json
import os
from datetime import datetime, timedelta, timezone
from mcp.server.fastmcp import FastMCP
from elasticsearch import Elasticsearch

ES_HOST = os.getenv("ES_HOST", "http://nss-elasticsearch:9200")
ES_USER = os.getenv("ES_USERNAME", "xdr-push")
ES_PASS = os.getenv("ES_PASSWORD", "")
MAX_EVENTS = int(os.getenv("MCP_MAX_EVENTS", "200"))
# IOC 库路径（按需部署，默认 /opt/ndr/so/ioc.json；文件不存在则 check_ioc 返回空匹配）
IOC_PATH = os.getenv("MCP_IOC_PATH", "/opt/ndr/so/ioc.json")

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS) if ES_PASS else None,
                   request_timeout=30, verify_certs=False)

mcp = FastMCP("ndr-analysis")

DATASETS = {
    "conn": "zeek.conn", "dns": "zeek.dns", "http": "zeek.http",
    "ssl": "zeek.ssl", "tls": "zeek.ssl", "smb": "zeek.smb_files",
    "smb_files": "zeek.smb_files", "smb_mapping": "zeek.smb_mapping",
    "ntlm": "zeek.ntlm", "files": "zeek.files", "ssh": "zeek.ssh",
}


def _load_ioc():
    """加载本地 IOC 库（每次调用重新读取，便于热更新）。

    格式：{"ips": [...], "domains": [...], "hashes": [...]}
    每条形如：{"value": "8.8.8.8", "type": "c2", "source": "manual", "severity": "high", "note": ""}
    """
    try:
        with open(IOC_PATH, encoding="utf-8") as f:
            d = json.load(f)
            return {
                "ips": d.get("ips", []),
                "domains": d.get("domains", []),
                "hashes": d.get("hashes", []),
            }
    except Exception:
        return {"ips": [], "domains": [], "hashes": []}


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


def _search_events_desc(index: str, filters: list[dict], size: int = MAX_EVENTS) -> list[dict]:
    """降序返回（用于 pcap / strelka 类"最新优先"查询）"""
    body = {
        "size": size,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": "desc"}],
    }
    resp = es.search(index=index, body=body)
    return [_summary(h["_source"]) for h in resp["hits"]["hits"]]


def _parse_pcap_ts(filename: str) -> datetime | None:
    """从 suricata pcap-log 文件名提取起始时间戳（filename: so-pcap.<iso-ts>.<thread>.pcap）"""
    import re
    m = re.match(r"so-pcap\.(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\.pcap$", filename)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1))
    except ValueError:
        return None


def _parse_pcap(filename: str, bpf_filter: str | None, max_packets: int) -> dict:
    """纯 Python pcap 解析器：返回包摘要列表（不依赖 tshark）。

    支持 BPF 子集：host X / src host X / dst host X / [src|dst] port X / tcp port X / udp port X
    多条件以 and 连接（不支持 or / not）。

    注意：pcap 文件头使用文件字节序（由 magic number 决定），但包内容始终是网络字节序
    （big-endian），与文件字节序无关——所有 IP/TCP/UDP 解析固定用 big-endian。
    """
    import struct
    NET = ">"  # 网络字节序（包数据固定用 big-endian）

    def parse_bpf(filt: str) -> dict:
        """解析 BPF 子集到 (field, op, value) 列表"""
        rules = []
        tokens = filt.strip().split()
        i = 0
        cur_dir = None  # None / 'src' / 'dst'
        while i < len(tokens):
            t = tokens[i]
            if t in ("src", "dst"):
                cur_dir = t
                i += 1
                continue
            if t == "host":
                ip = tokens[i + 1]
                rules.append(("host", cur_dir, ip))
                cur_dir = None
                i += 2
                continue
            if t == "port":
                port = int(tokens[i + 1])
                rules.append(("port", cur_dir, port))
                cur_dir = None
                i += 2
                continue
            if t == "tcp":
                i += 1
                if i < len(tokens) and tokens[i] == "port":
                    rules.append(("port_proto", cur_dir, "tcp", int(tokens[i + 1])))
                    cur_dir = None
                    i += 2
                continue
            if t == "udp":
                i += 1
                if i < len(tokens) and tokens[i] == "port":
                    rules.append(("port_proto", cur_dir, "udp", int(tokens[i + 1])))
                    cur_dir = None
                    i += 2
                continue
            if t == "and":
                i += 1
                continue
            i += 1  # 跳过未知 token
        return rules

    def match(rules: list, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> bool:
        for r in rules:
            if r[0] == "host":
                _, d, ip = r
                if d == "src" and src_ip != ip:
                    return False
                if d == "dst" and dst_ip != ip:
                    return False
                if d is None and src_ip != ip and dst_ip != ip:
                    return False
            elif r[0] == "port":
                _, d, port = r
                if d == "src" and src_port != port:
                    return False
                if d == "dst" and dst_port != port:
                    return False
                if d is None and src_port != port and dst_port != port:
                    return False
            elif r[0] == "port_proto":
                _, d, p, port = r
                if p != proto:
                    return False
                if d == "src" and src_port != port:
                    return False
                if d == "dst" and dst_port != port:
                    return False
                if d is None and src_port != port and dst_port != port:
                    return False
        return True if rules else True

    pcap_dir = os.getenv("MCP_PCAP_DIR", "/nsm/suripcap")
    # 路径校验：禁止 .. 穿越，只能解析 pcap_dir 下的文件名
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return {"error": f"非法文件名: {filename}（仅允许 basename）"}
    filepath = os.path.join(pcap_dir, filename)
    if not os.path.isfile(filepath):
        return {"error": f"文件不存在: {filepath}"}

    rules = parse_bpf(bpf_filter) if bpf_filter else []

    try:
        with open(filepath, "rb") as f:
            # Global header (24 bytes)
            gh = f.read(24)
            if len(gh) < 24:
                return {"error": "pcap global header 不完整"}
            magic = struct.unpack("<I", gh[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = "<"
            elif magic == 0xd4c3b2a1:
                endian = ">"
            else:
                return {"error": f"非 pcap 文件（magic=0x{magic:08x}）"}
            ver_major, ver_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(endian + "HHIIII", gh[4:24])

            packets = []
            count = 0
            total_bytes = 0
            ts_first = None
            ts_last = None
            proto_count = {"tcp": 0, "udp": 0, "other": 0}

            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", hdr)
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break
                count += 1
                total_bytes += incl_len
                ts_iso = datetime.fromtimestamp(ts_sec + ts_usec / 1e6, tz=timezone.utc).isoformat()
                if ts_first is None:
                    ts_first = ts_iso
                ts_last = ts_iso

                # 仅 Ethernet + IPv4 + TCP/UDP 解析（linktype=1）；其他类型记录但不解
                if linktype != 1 or len(data) < 14:
                    proto_count["other"] += 1
                    if len(packets) < max_packets:
                        packets.append({"ts": ts_iso, "length": incl_len, "note": "non-ethernet or truncated"})
                    continue

                ethertype = struct.unpack(NET + "H", data[12:14])[0]
                if ethertype != 0x0800 or len(data) < 34:
                    proto_count["other"] += 1
                    if len(packets) < max_packets:
                        packets.append({"ts": ts_iso, "length": incl_len, "note": "non-ipv4 or truncated"})
                    continue

                ip = data[14:]
                if len(ip) < 20:
                    continue
                ihl = (ip[0] & 0x0f) * 4
                proto = ip[9]
                src_ip = ".".join(str(b) for b in ip[12:16])
                dst_ip = ".".join(str(b) for b in ip[16:20])

                src_port = dst_port = 0
                proto_name = "other"
                if proto == 6 and len(ip) >= ihl + 4:  # TCP
                    tcp = ip[ihl:]
                    src_port, dst_port = struct.unpack(NET + "HH", tcp[:4])
                    proto_name = "tcp"
                    proto_count["tcp"] += 1
                elif proto == 17 and len(ip) >= ihl + 4:  # UDP
                    udp = ip[ihl:]
                    src_port, dst_port = struct.unpack(NET + "HH", udp[:4])
                    proto_name = "udp"
                    proto_count["udp"] += 1
                else:
                    proto_count["other"] += 1

                if not match(rules, src_ip, dst_ip, src_port, dst_port, proto_name):
                    continue

                if len(packets) < max_packets:
                    packets.append({
                        "ts": ts_iso,
                        "src_ip": src_ip, "src_port": src_port,
                        "dst_ip": dst_ip, "dst_port": dst_port,
                        "protocol": proto_name,
                        "length": incl_len,
                    })

            return {
                "file": filename,
                "size_bytes": os.path.getsize(filepath),
                "version": f"{ver_major}.{ver_minor}",
                "linktype": linktype,
                "snaplen": snaplen,
                "packet_count": count,
                "total_bytes": total_bytes,
                "proto_breakdown": proto_count,
                "ts_first": ts_first,
                "ts_last": ts_last,
                "bpf_filter": bpf_filter,
                "matched_packets": packets,
                "truncated": count > max_packets and len(packets) == max_packets,
            }
    except Exception as e:
        return {"error": f"pcap 解析失败: {e}"}


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


@mcp.tool()
def get_alert_chain(target: dict, datasets: list[str] | None = None,
                    window_seconds: int = 3600, max_events: int = 500) -> dict:
    """按时间窗合并多数据集事件，按 @timestamp 升序返回（攻击链重建）。

    适用场景：分析"这个 community_id / IP 在过去 1 小时里做了什么"，按发生顺序呈现
    conn/dns/http/ssl/smb_files 等事件，便于 LLM 推断"先做了什么 → 再做了什么 → 触发了什么"。

    Args:
        target: {"community_id": "...", "src_ip": "...", "dst_ip": "...", "uid": "..."} 至少一项
        datasets: 数据集列表（默认 conn/dns/http/ssl/smb_files/smb_mapping/ntlm/files）
        window_seconds: 回溯窗口（秒），默认 3600
        max_events: 跨数据集总事件上限（默认 500，防 token 爆炸；超出则截断最早事件）
    """
    if not target or not any(target.values()):
        return {"error": "target 至少需要 community_id/src_ip/dst_ip/uid 之一"}
    ds_list = datasets or ["conn", "dns", "http", "ssl", "smb_files", "smb_mapping", "ntlm", "files"]
    start, end = _time_range(window_seconds)
    base_filters = [
        {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}
    ] + _target_filter(target)

    merged: list[dict] = []
    per_dataset: dict[str, int] = {}
    errors: dict[str, str] = {}
    for ds in ds_list:
        es_ds = DATASETS.get(str(ds).lower())
        if not es_ds:
            errors[ds] = "unknown dataset"
            continue
        filters = [{"term": {"event.dataset": es_ds}}] + base_filters
        try:
            events = _search_events("logs-zeek-so", filters, size=max_events)
            per_dataset[ds] = len(events)
            merged.extend(events)
        except Exception as e:
            errors[ds] = str(e)
            per_dataset[ds] = 0

    # 跨数据集排序
    merged.sort(key=lambda e: (e.get("@timestamp") or "", e.get("event.dataset") or ""))

    # 超限时保留最新 N 条（最旧的事件先被裁掉，因已排好序）
    truncated = len(merged) > max_events
    if truncated:
        merged = merged[-max_events:]

    return {
        "window_seconds": window_seconds,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "target": target,
        "per_dataset_counts": per_dataset,
        "events": merged,
        "total": len(merged),
        "truncated": truncated,
        "errors": errors,
    }


@mcp.tool()
def query_pcaps(window_seconds: int = 3600, limit: int = 50) -> dict:
    """查询覆盖指定时间窗的 pcap 全包文件清单（suricata 落盘的 so-pcap.*）。

    文件名规则：so-pcap.<ISO8601 起始时间>.<线程编号>.pcap
    单个文件大小上限见 suricata.pcap.file_size_mb（默认 1000MB），轮转时按大小或线程切换。

    Args:
        window_seconds: 回溯窗口（秒），默认 3600
        limit: 返回文件数上限（默认 50）

    注意：本工具只列出文件清单与元数据；按 IP/协议过滤包内容需外部 tshark / Wireshark
    离线分析，NDR 暂不内嵌。下载请走 ndr-manager 的 /api/pcap/<name> 端点
    （要求探针用户会话认证 + 路径校验防穿越）。
    """
    pcap_dir = os.getenv("MCP_PCAP_DIR", "/nsm/suripcap")
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=max(window_seconds, 1))

    files = []
    try:
        for name in sorted(os.listdir(pcap_dir)):
            if not name.startswith("so-pcap."):
                continue
            full = os.path.join(pcap_dir, name)
            if not os.path.isfile(full):
                continue
            stat = os.stat(full)
            ts = _parse_pcap_ts(name)
            files.append({
                "name": name,
                "path": full,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / 1e6, 2),
                "start_time": ts.isoformat() if ts else None,
                "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
    except FileNotFoundError:
        return {"error": f"pcap 目录不存在: {pcap_dir}（suricata 是否在跑？是否挂载？）"}

    # 仅保留起始时间在时间窗内的文件
    in_window = [f for f in files if f["start_time"] and f["start_time"] >= start.isoformat()]
    in_window.sort(key=lambda f: f["start_time"], reverse=True)
    in_window = in_window[:limit]

    return {
        "pcap_dir": pcap_dir,
        "window_seconds": window_seconds,
        "from": start.isoformat(),
        "to": now.isoformat(),
        "files": in_window,
        "total_in_window": len(in_window),
        "total_on_disk": len(files),
    }


@mcp.tool()
def analyze_pcap(filename: str, bpf_filter: str | None = None,
                max_packets: int = 100) -> dict:
    """解析 suricata pcap 全包文件，返回包摘要（ts / src-dst / proto / length）。

    支持 BPF 子集（仅 Ethernet + IPv4 + TCP/UDP）：
    - "host <ip>"                双向匹配
    - "src host <ip>" / "dst host <ip>"
    - "<src|dst> port <port>"
    - "tcp port <port>" / "udp port <port>"
    - 多条件以 and 连接（不支持 or / not）

    Args:
        filename: pcap 文件名（basename；不允许路径穿越）
        bpf_filter: 可选 BPF 过滤字符串
        max_packets: 返回包摘要上限（默认 100；纯 Python 流式解析，超限仅截断摘要列表）

    实现：纯 Python pcap 解析（不依赖 tshark/wireshark）；可移植到任何环境。
    完整协议解码（HTTP payload / TLS SNI）需外部 tshark，NDR 暂不内嵌。
    """
    return _parse_pcap(filename, bpf_filter, max_packets)


@mcp.tool()
def aggregate_suricata(target: dict, window_seconds: int = 3600,
                        field: str = "rule.name", top_n: int = 10) -> dict:
    """Suricata 告警聚合（按规则 / IP / 端口等维度），对应 logs-suricata.alerts-so。

    与 `aggregate_stats`（仅 zeek 索引）互补，补全"按 Suricata 维度聚合"的能力。
    典型用法：找出最近 1 小时触发最多的告警规则、Top 攻击源 IP 等。

    Args:
        target: 目标定位（community_id / src_ip / dst_ip）
        window_seconds: 回溯窗口（秒），默认 3600
        field: 聚合字段，如 rule.name / rule.uuid / source.ip / destination.ip /
               source.port / destination.port / event.severity
        top_n: 返回条数（默认 10）
    """
    if not target or not any(target.values()):
        return {"error": "target 至少需要 community_id/src_ip/dst_ip 之一"}
    start, end = _time_range(window_seconds)
    filters = [
        {"term": {"event.dataset": "suricata.alert"}},
        {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
    ] + _target_filter(target)
    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {"top": {"terms": {"field": field, "size": top_n}}},
    }
    try:
        resp = es.search(index="logs-suricata.alerts-so", body=body)
    except Exception as e:
        return {"error": str(e)}
    buckets = resp.get("aggregations", {}).get("top", {}).get("buckets", [])
    total = resp.get("hits", {}).get("total", {}).get("value", 0)
    return {
        "field": field,
        "window_seconds": window_seconds,
        "target": target,
        "total_alerts": total,
        "top": [{"key": b["key"], "count": b["doc_count"]} for b in buckets],
    }


@mcp.tool()
def get_indicators(target: dict, window_seconds: int = 3600,
                   max_events: int = 200) -> dict:
    """跨 3 索引（suricata.clues + zeek.metadata + strelka.files）统一查询同一目标的所有痕迹。

    适用场景：拿到一个 IP / community_id，想一次性看到"它出现在了哪些数据源里"，
    替代 LLM 手动依次调用 get_clue / correlate_session / query_files 三次。

    返回事件按来源打标签（source: "suricata.alert" / "zeek.<ds>" / "strelka.file"），
    按 @timestamp 升序排列，最多 max_events 条（超出截断最早 + 最后统计）。

    Args:
        target: 目标定位（community_id / src_ip / dst_ip），至少一项
        window_seconds: 回溯窗口（秒），默认 3600
        max_events: 跨源最大事件数（默认 200；超限保留最新）
    """
    if not target or not any(target.values()):
        return {"error": "target 至少需要 community_id/src_ip/dst_ip 之一"}
    start, end = _time_range(window_seconds)
    base_time = {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}
    base_target = _target_filter(target)

    events = []
    counts = {}
    errors = {}

    # 1) Suricata 线索
    try:
        resp = es.search(
            index="logs-suricata.alerts-so",
            body={
                "size": max_events,
                "query": {"bool": {"filter": [
                    {"term": {"event.dataset": "suricata.alert"}},
                    base_time,
                ] + base_target}},
                "sort": [{"@timestamp": "asc"}],
            },
        )
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            events.append({
                "ts": s.get("@timestamp"),
                "source": "suricata.alert",
                "rule": (s.get("rule") or {}).get("name"),
                "src_ip": (s.get("source") or {}).get("ip"),
                "dst_ip": (s.get("destination") or {}).get("ip"),
                "severity": (s.get("event") or {}).get("severity"),
            })
        counts["suricata.alert"] = resp["hits"]["total"]["value"]
    except Exception as e:
        errors["suricata.alert"] = str(e)

    # 2) Zeek 元数据（按 dataset 拆分，每数据集 max_events）
    for ds_short, ds_event in DATASETS.items():
        try:
            resp = es.search(
                index="logs-zeek-so",
                body={
                    "size": max_events,
                    "query": {"bool": {"filter": [
                        {"term": {"event.dataset": ds_event}},
                        base_time,
                    ] + base_target}},
                    "sort": [{"@timestamp": "asc"}],
                },
            )
            for h in resp["hits"]["hits"]:
                s = _summary(h["_source"])
                s["source"] = ds_event
                events.append(s)
            counts[ds_event] = resp["hits"]["total"]["value"]
        except Exception as e:
            errors[ds_event] = str(e)

    # 3) Strelka 文件分析
    try:
        resp = es.search(
            index="logs-strelka-so",
            body={
                "size": max_events,
                "query": {"bool": {"filter": [base_time] + base_target}},
                "sort": [{"@timestamp": "asc"}],
            },
        )
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            events.append({
                "ts": s.get("@timestamp"),
                "source": "strelka.file",
                "md5": (s.get("file") or {}).get("hash", {}).get("md5"),
                "mime_type": (s.get("file") or {}).get("mime_type"),
                "yara": (s.get("strelka") or {}).get("yara"),
            })
        counts["strelka.file"] = resp["hits"]["total"]["value"]
    except Exception as e:
        errors["strelka.file"] = str(e)

    # 按时间排序，超限保留最新
    events.sort(key=lambda e: (e.get("ts") or "", e.get("source") or ""))
    truncated = len(events) > max_events
    if truncated:
        events = events[-max_events:]

    return {
        "window_seconds": window_seconds,
        "target": target,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "per_source_counts": counts,
        "total_events": sum(counts.values()),
        "returned": len(events),
        "truncated": truncated,
        "events": events,
        "errors": errors,
    }


@mcp.tool()
def check_ioc(target: dict) -> dict:
    """本地 IOC 库比对（IP / domain / MD5）。

    IOC 库路径通过 MCP_IOC_PATH 配置（默认 /opt/ndr/so/ioc.json）；文件不存在返回空。
    每次调用重新加载文件，便于运维热更新（无需重启 mcp-server）。

    对 target 中的每个字段，匹配 IOC 库对应类别，返回 hits（命中列表）+ matched（布尔）。
    例如 target={"src_ip": "8.8.8.8"} 会去 ioc.ips 里查找是否包含 "8.8.8.8"。

    Args:
        target: {"src_ip": "...", "dst_ip": "...", "dns.question.name": "...", "file.hash.md5": "..."}
    """
    def normalize(hits):
        return [{
            "value": h.get("value"),
            "type": h.get("type"),          # c2 / malware / scanner / phishing / ...
            "source": h.get("source"),      # IOC 来源标识
            "severity": h.get("severity"),  # critical / high / medium / low
            "note": h.get("note", ""),
        } for h in hits]

    ioc = _load_ioc()
    hits = {"ip": [], "domain": [], "hash": []}

    # IP 匹配（src_ip / dst_ip 都对比）
    for k in ("src_ip", "dst_ip"):
        v = target.get(k)
        if v:
            for entry in ioc.get("ips", []):
                if entry.get("value") == v:
                    hits["ip"].append({"field": k, **entry})

    # Domain 匹配（dns.question.name / tls.server.name）
    for k in ("dns.question.name", "tls.server.name"):
        v = target.get(k)
        if v:
            for entry in ioc.get("domains", []):
                if entry.get("value") == v:
                    hits["domain"].append({"field": k, **entry})

    # Hash 匹配（file.hash.md5 / file.hash.sha256）
    for k in ("file.hash.md5", "file.hash.sha256", "md5"):
        v = target.get(k)
        if v:
            for entry in ioc.get("hashes", []):
                if entry.get("value", "").lower() == v.lower():
                    hits["hash"].append({"field": k, **entry})

    total = sum(len(v) for v in hits.values())
    return {
        "ioc_path": IOC_PATH,
        "ioc_loaded": {
            "ips": len(ioc.get("ips", [])),
            "domains": len(ioc.get("domains", [])),
            "hashes": len(ioc.get("hashes", [])),
        },
        "target": target,
        "matched": total > 0,
        "hit_count": total,
        "hits": {
            "ip": normalize(hits["ip"]),
            "domain": normalize(hits["domain"]),
            "hash": normalize(hits["hash"]),
        },
    }


if __name__ == "__main__":
    # streamable HTTP 传输：Agent 通过 http://nss-mcp-server:8000/mcp 远程调用
    mcp.run(transport="streamable-http")
