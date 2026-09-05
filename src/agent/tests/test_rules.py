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


# ---- D1: 跨批滚动窗口(Redis 累积,rule.window 生效)----

def _windowed_engine():
    import fakeredis.aioredis

    from app.rules.window_store import RuleWindowStore

    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = RuleWindowStore(client)
    return RuleEngine(rules_dir="config/rules", window_store=store), store


def _smb_conn(event_id, src, dst, ts="2026-09-05T01:00:00Z"):
    from app.schemas.event import EventEnvelope

    return EventEnvelope(
        event_id=event_id,
        ts=ts,
        src_ip=src,
        src_port="50000",
        dst_ip=dst,
        dst_port="445",
        proto="tcp",
        dataset="zeek.connection",
        zeek={"conn_state": "S0", "service": "smb"},
    )


async def test_windowed_smb_bruteforce_hits_across_batches():
    """BEH-001(src→≥3 distinct dst:445/300s):三批各打一个 dst,第 3 批命中。"""
    engine, _ = _windowed_engine()
    t0 = 1_800_000_000_000  # 固定毫秒时钟
    # 批1: dst1
    hits1 = await engine.evaluate_windowed([_smb_conn("a1", "10.0.0.7", "10.0.0.21")], now_ms=t0)
    assert all(not hs for hs in hits1.values())
    # 批2: dst2(窗口内累计 2 个 distinct)
    hits2 = await engine.evaluate_windowed([_smb_conn("a2", "10.0.0.7", "10.0.0.22")], now_ms=t0 + 10_000)
    assert all(not hs for hs in hits2.values())
    # 批3: dst3 → 窗口内 3 个 distinct dst → 命中,挂在当前批会话上
    hits3 = await engine.evaluate_windowed([_smb_conn("a3", "10.0.0.7", "10.0.0.23")], now_ms=t0 + 20_000)
    sess3 = "sess:10.0.0.7:10.0.0.23:445:tcp"
    assert sess3 in hits3
    assert [h.behavior_id for h in hits3[sess3]] == ["BEH-001"]
    assert hits3[sess3][0].count == 3
    # 早先批的会话不应被回挂(它们处理时尚未达阈值)
    assert "sess:10.0.0.7:10.0.0.21:445:tcp" not in hits3


async def test_window_expiry_prunes_old_events():
    """超过 window(300s)的旧事件被剪枝 → 重新累计。"""
    engine, _ = _windowed_engine()
    t0 = 1_800_000_000_000
    for i, dst in enumerate(("10.0.0.21", "10.0.0.22")):
        await engine.evaluate_windowed([_smb_conn(f"x{i}", "10.0.0.9", dst)], now_ms=t0 + i * 10_000)
    # 400s 后:前两批已出窗,只打一个 dst → 不应命中
    hits = await engine.evaluate_windowed([_smb_conn("x3", "10.0.0.9", "10.0.0.23")], now_ms=t0 + 400_000)
    assert all(not hs for hs in hits.values())


async def test_windowed_fallback_without_store_matches_pure():
    """无 window_store 时 evaluate_windowed 回退纯批求值,行为与 evaluate 一致。"""
    engine = RuleEngine(rules_dir="config/rules")
    # 用单批 SSH 爆破事件(25 条同批)验证窗口/纯批一致
    from app.schemas.event import EventEnvelope

    evs = [
        EventEnvelope(
            event_id=f"s{i}",
            ts="2026-08-29T10:00:00Z",
            src_ip="10.0.0.30",
            src_port=str(40000 + i),
            dst_ip="10.0.0.10",
            dst_port="22",
            proto="tcp",
            dataset="zeek.connection",
            enriched={"conn_state": "REJ" if i % 2 else "SF"},
        )
        for i in range(25)
    ]
    pure = engine.evaluate(evs)
    win = await engine.evaluate_windowed(evs)
    assert pure == win


async def test_windowed_ssh_bruteforce_counts_across_batches():
    """BEH-006(会话 scope):同 (src,dst,22) 20 次尝试跨批累积后命中。"""
    engine, _ = _windowed_engine()
    t0 = 1_800_000_000_000

    def ssh(i, state):
        from app.schemas.event import EventEnvelope

        return EventEnvelope(
            event_id=f"ssh{i}",
            ts="2026-09-05T01:00:00Z",
            src_ip="10.0.0.30",
            src_port=str(41000 + i),
            dst_ip="10.0.0.10",
            dst_port="22",
            proto="tcp",
            dataset="zeek.connection",
            zeek={"conn_state": state},
        )

    # 先打 19 条(分 4 批) → 未达 20
    for i in range(19):
        hits = await engine.evaluate_windowed([ssh(i, "SF" if i % 2 else "REJ")], now_ms=t0 + i * 1_000)
        assert all(not hs for hs in hits.values())
    # 第 20 条(失败占比高:REJ/SF → failed_ratio 满足) → 命中
    hits = await engine.evaluate_windowed([ssh(19, "REJ")], now_ms=t0 + 19_000)
    sess = "sess:10.0.0.30:10.0.0.10:22:tcp"
    assert sess in hits
    assert "BEH-006" in [h.behavior_id for h in hits[sess]]


def test_weird_features_summarized():
    """P1-B:zeek.weird 会话应产出 names/notice_count 特征供模型研判。"""
    from app.schemas.event import EventEnvelope

    events = [
        EventEnvelope(
            event_id=f"w{i}",
            ts="2026-09-05T01:00:00Z",
            src_ip="10.0.0.7",
            src_port="40000",
            dst_ip="10.0.0.21",
            dst_port="445",
            proto="",
            dataset="zeek.weird",
            zeek={"name": "possible_SPF_DoS", "notice": True},
        )
        for i in range(3)
    ]
    engine = RuleEngine(rules_dir="config/rules")
    hits = engine.evaluate(events)
    unit = engine.build_unit("sess:10.0.0.7:10.0.0.21:445:", events, hits.get("sess:10.0.0.7:10.0.0.21:445:", []))
    feats = unit.summary.get("features", {}).get("zeek.weird", {})
    assert feats.get("names") == ["possible_spf_dos"] or feats.get("names") == ["possible_SPF_DoS"] or "possible" in str(feats)
    assert feats.get("notice_count") == 3
