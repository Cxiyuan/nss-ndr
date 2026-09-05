"""输入侧重心:会话分组 proto 回填测试(2026-09-05)。"""

from app.pipeline.grouping import backfill_proto, group_by_session
from app.schemas.event import EventEnvelope


def _ev(eid, src, dst, port, proto, dataset, zeek=None):
    return EventEnvelope(
        event_id=eid, ts="2026-09-05T01:00:00Z", src_ip=src, src_port="50000",
        dst_ip=dst, dst_port=port, proto=proto, dataset=dataset, zeek=zeek or {},
    )


def test_backfill_proto_merges_ssh_into_conn_session():
    """同流 conn(tcp)+ssh(proto 空)+weird(proto 空)应并入同一会话。"""
    evs = [
        _ev("c1", "10.0.0.30", "10.0.0.10", "22", "tcp", "zeek.connection", {"conn_state": "REJ"}),
        _ev("s1", "10.0.0.30", "10.0.0.10", "22", "", "zeek.ssh", {"auth_attempts": "3"}),
        _ev("w1", "10.0.0.30", "10.0.0.10", "22", "", "zeek.weird", {"name": "x", "notice": False}),
    ]
    groups = group_by_session(evs, ["e1", "e2", "e3"])
    assert set(groups) == {"sess:10.0.0.30:10.0.0.10:22:tcp"}
    merged = groups["sess:10.0.0.30:10.0.0.10:22:tcp"][0]
    assert {e.dataset for e in merged} == {"zeek.connection", "zeek.ssh", "zeek.weird"}
    # 无 conn 兄弟时不误填(保持原 proto 语义)
    solo = [_ev("x1", "10.0.0.1", "10.0.0.2", "53", "", "zeek.weird", {"name": "y"})]
    backfill_proto(solo)
    assert solo[0].proto == ""


def test_backfill_proto_prefers_tcp_first_seen():
    evs = [
        _ev("u1", "A", "B", "53", "udp", "zeek.dns", {}),
        _ev("t1", "A", "B", "53", "tcp", "zeek.connection", {}),
        _ev("w1", "A", "B", "53", "", "zeek.weird", {}),
    ]
    groups = group_by_session(evs)
    keys = set(groups)
    # 同 (A,B,53):dns udp 独立;tcp conn 与 weird 并入 tcp
    assert "sess:A:B:53:udp" in keys
    assert "sess:A:B:53:tcp" in keys
    tcp_evs = {e.event_id for e in groups["sess:A:B:53:tcp"][0]}
    assert tcp_evs == {"t1", "w1"}
