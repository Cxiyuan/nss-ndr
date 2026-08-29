from app.rules import RuleEngine


def test_ssh_bruteforce_hit(events_ssh_bruteforce):
    engine = RuleEngine(rules_dir="config/rules")
    hits = engine.evaluate(events_ssh_bruteforce)
    sess = "sess:10.0.0.30:10.0.0.10:22:tcp"
    assert sess in hits
    ids = [h.behavior_id for h in hits[sess]]
    assert "BEH-006" in ids
    unit = engine.build_unit(sess, events_ssh_bruteforce, hits[sess])
    assert unit.initial_risk == "medium"
    assert not unit.rule_resolved
    assert unit.event_count == 25


def test_port_scan_direct_rule():
    from app.schemas.event import EventEnvelope
    from app.schemas.keys import session_key

    events = [
        EventEnvelope(
            event_id=f"p{i}",
            ts="2026-08-29T10:00:00Z",
            src_ip="10.0.0.99",
            src_port=str(20000 + i),
            dst_ip="10.0.0.50",
            dst_port=str(1000 + i),
            proto="tcp",
            dataset="zeek.connection",
        )
        for i in range(60)
    ]
    engine = RuleEngine(rules_dir="config/rules")
    hits = engine.evaluate(events)
    sess = session_key("10.0.0.99", "10.0.0.50", "1000", "tcp")
    # 端口扫描是 custom 分组（src+dst），命中挂到涉及的所有会话
    assert any("BEH-005" in [h.behavior_id for h in hs] for hs in hits.values())
    unit = engine.build_unit(sess, events, hits.get(sess, []))
    assert unit.rule_resolved  # model=never 直接判定
    assert unit.initial_risk == "low"


def test_no_hits_for_normal_traffic():
    from app.schemas.event import EventEnvelope

    events = [
        EventEnvelope(
            event_id=f"n{i}",
            ts="2026-08-29T10:00:00Z",
            src_ip="10.0.0.1",
            src_port=str(30000 + i),
            dst_ip="10.0.0.2",
            dst_port="443",
            proto="tcp",
            dataset="zeek.connection",
            enriched={"conn_state": "SF"},
        )
        for i in range(3)
    ]
    engine = RuleEngine(rules_dir="config/rules")
    hits = engine.evaluate(events)
    assert all(not hs for hs in hits.values())
