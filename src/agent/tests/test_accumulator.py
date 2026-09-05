"""P3 跨批会话累积器测试(2026-09-05)。"""

from app.pipeline.accumulator import EpisodeAccumulator
from app.schemas.event import EventEnvelope


def _ev(eid, src="A", dst="B", port="22", proto="tcp", ds="zeek.connection"):
    return EventEnvelope(event_id=eid, ts="2026-09-05T01:00:00Z", src_ip=src, src_port="1",
                         dst_ip=dst, dst_port=port, proto=proto, dataset=ds)


def test_idle_flush():
    acc = EpisodeAccumulator(flush_idle=12.0, max_events=200, max_age=300.0, max_sessions=10)
    t0 = 1000.0
    acc.add("A", "B", "22", _ev("e1"), "1-0", t0)
    acc.add("A", "B", "22", _ev("e2"), "2-0", t0 + 2)
    assert acc.ripe_keys(t0 + 5) == []            # 未空闲(last=t0+2, idle=3)
    assert acc.ripe_keys(t0 + 13) == []           # idle=11 < 12
    assert acc.ripe_keys(t0 + 14) == [("A", "B", "22")]  # idle=12 → flush
    events, ids = acc.pop(("A", "B", "22"))
    assert len(events) == 2 and len(ids) == 2


def test_max_events_flush():
    acc = EpisodeAccumulator(max_events=3)
    t0 = 1000.0
    for i in range(3):
        acc.add("A", "B", "22", _ev(f"e{i}"), f"{i}-0", t0 + i)
    assert acc.ripe_keys(t0 + 2) == [("A", "B", "22")]


def test_max_age_flush():
    acc = EpisodeAccumulator(flush_idle=12.0, max_age=60.0)
    t0 = 1000.0
    acc.add("A", "B", "22", _ev("e1"), "1-0", t0)
    # 事件持续小间隔出现,但总存活超 max_age → flush
    acc.add("A", "B", "22", _ev("e2"), "2-0", t0 + 30)
    assert acc.ripe_keys(t0 + 30) == []
    assert acc.ripe_keys(t0 + 61) == [("A", "B", "22")]


def test_dedup_event_and_entry():
    acc = EpisodeAccumulator(flush_idle=1.0)
    t0 = 1000.0
    ev = _ev("dup")
    acc.add("A", "B", "22", ev, "id1", t0)
    acc.add("A", "B", "22", ev, "id1", t0 + 0.5)   # 同 event+同 entry 重投
    acc.add("A", "B", "22", ev, "id2", t0 + 1.0)   # 同 event 新 entry(claim 重投)
    events, ids = acc.pop(("A", "B", "22"))
    assert len(events) == 1                          # 事件只存一次
    assert ids == ["id1", "id2"]                     # entry 都待 ack(去重后)


def test_pressure_flush_oldest():
    acc = EpisodeAccumulator(max_sessions=2)
    t0 = 1000.0
    acc.add("A", "B", "22", _ev("a"), "1-0", t0)
    acc.add("C", "D", "80", _ev("c"), "2-0", t0 + 1)
    acc.add("E", "F", "443", _ev("e"), "3-0", t0 + 2)  # 超上限
    keys = acc.ripe_keys(t0 + 2)
    assert ("A", "B", "22") in keys                    # 最旧被标记 flush
    acc.pop(("A", "B", "22"))                          # caller 负责 pop
    assert len(acc) == 2
