"""输入侧会话分组辅助(2026-09-05 输入重心)。

背景(docs/research/agent-input-format-v2-2026-09-05.md §P2-B):zeek.ssh/zeek.weird 等
日志不携带 L4 proto 字段(ssh.log/weird.log 无 proto 列)→ 透传事件 proto 为空,
session_key 把 proto 归一为 "*",与同流 conn 事件(proto=tcp)拆成两个会话
(实测同一 SSH 爆破流同时存在 ':22:tcp'(conn)与 ':22:*'(weird+ssh)),
导致模型分析 SSH 爆破时看不到 ssh.log 的 auth_attempts、conn 侧也看不到 weird 异常。

修复:批内按 (src_ip, dst_ip, dst_port) 找到带 proto 的兄弟事件(conn 等)回填空 proto,
使同流各数据流事件并入同一会话,分析上下文完整。
"""
from __future__ import annotations

from collections import defaultdict

from app.schemas.event import EventEnvelope
from app.schemas.keys import session_key


def backfill_proto(events: list[EventEnvelope]) -> None:
    """原地回填:proto 为空/* 的事件,取同批内同 (src,dst,dst_port) 兄弟事件的 proto。

    优先级:zeek.connection(权威 L4)行优先,其次任意带 proto 的行;首个非空即用。
    """
    if not events:
        return
    by_tuple: dict[tuple[str, str, str], str] = {}
    # 第一遍:conn 行(最可靠)
    for e in events:
        if e.dataset == "zeek.connection" and e.proto and e.proto != "*":
            by_tuple.setdefault((e.src_ip, e.dst_ip, e.dst_port), e.proto)
    # 第二遍:其它带 proto 的行兜底
    for e in events:
        if e.proto and e.proto != "*":
            by_tuple.setdefault((e.src_ip, e.dst_ip, e.dst_port), e.proto)
    if not by_tuple:
        return
    for e in events:
        if not e.proto or e.proto == "*":
            p = by_tuple.get((e.src_ip, e.dst_ip, e.dst_port))
            if p:
                e.proto = p


def group_by_session(
    events: list[EventEnvelope], entry_ids: list[str] | None = None
) -> dict[str, tuple[list[EventEnvelope], list[str]]]:
    """worker.run_once 的批内会话分组:proto 回填 → session_key 分组。

    entry_ids 与 events 等长(一一对应),缺省给空列表。
    """
    backfill_proto(events)
    ids = entry_ids or [""] * len(events)
    groups: dict[str, tuple[list[EventEnvelope], list[str]]] = defaultdict(lambda: ([], []))
    for ev, eid in zip(events, ids):
        sess = session_key(ev.src_ip, ev.dst_ip, ev.dst_port, ev.proto)
        groups[sess][0].append(ev)
        groups[sess][1].append(eid)
    return dict(groups)
