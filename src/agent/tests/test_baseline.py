import math
import random

import pytest

from app.baseline import BaselineConfig, BaselineEngine, TDigest
from app.schemas.event import EventEnvelope


def _events(ip: str, count: int, dst_base: int = 0, conn_state: str = "SF", dataset: str = "zeek.connection") -> list[EventEnvelope]:
    return [
        EventEnvelope(
            event_id=f"{ip}-{dst_base}-{i}",
            ts="2026-08-29T10:00:00Z",
            src_ip=ip,
            src_port=str(40000 + i),
            dst_ip=f"10.0.0.{1 + (i + dst_base) % 10}",
            dst_port=str(1024 + (i + dst_base) % 50),
            proto="tcp",
            dataset=dataset,
            enriched={"conn_state": conn_state},
        )
        for i in range(count)
    ]


def test_tdigest_quantiles():
    t = TDigest(compression=50)
    random.seed(42)
    data = [random.gauss(100, 10) for _ in range(5000)]
    for x in data:
        t.add(x)
    assert abs(t.quantile(0.5) - 100) < 2
    assert abs(t.quantile(0.25) - (100 - 0.6745 * 10)) < 3
    assert abs(t.quantile(0.95) - (100 + 1.645 * 10)) < 5
    assert t.n == pytest.approx(5000)


def test_tdigest_merge_roundtrip():
    t1, t2 = TDigest(), TDigest()
    for x in range(100):
        t1.add(x)
    for x in range(100, 200):
        t2.add(x)
    t1.merge(t2)
    assert t1.n == pytest.approx(200)
    assert 98 <= t1.median() <= 101  # 连续 0..199 的中位数 ≈ 99.5
    restored = TDigest.from_dict(t1.to_dict())
    assert restored.quantile(0.5) == pytest.approx(t1.quantile(0.5))


def _small_config() -> BaselineConfig:
    return BaselineConfig(learn_min_samples=20, loose_min_samples=60, alert_threshold=3.0)


def test_shadow_phase_records_without_alert():
    eng = BaselineEngine(_small_config())
    for i in range(15):
        res = eng.observe_and_evaluate(_events("10.0.1.1", 5, dst_base=i))
    r = res["10.0.1.1"]
    assert r.phase == "shadow"
    assert r.alert is False
    assert r.confidence < 1.0


def test_detect_spike_after_learning():
    eng = BaselineEngine(_small_config())
    # 学习期：正常流量（每个批次 5 条连接）
    for i in range(70):
        eng.observe_and_evaluate(_events("10.0.1.2", 5, dst_base=i))
    r_norm = eng.observe_and_evaluate(_events("10.0.1.2", 5, dst_base=999))["10.0.1.2"]
    assert r_norm.alert is False
    # 异常突刺：一次 500 条连接 + 50 个不同端口（超出基线 P99 + 3×MAD）
    spike = _events("10.0.1.2", 500, dst_base=100000)
    r = eng.observe_and_evaluate(spike)["10.0.1.2"]
    assert r.phase == "converged"
    assert r.score >= r.threshold
    assert r.alert is True
    assert "conn_count" in r.dimensions


def test_alert_budget():
    eng = BaselineEngine(_small_config())
    for i in range(70):
        eng.observe_and_evaluate(_events("10.0.1.3", 5, dst_base=i))
    alerts = 0
    for _ in range(10):
        r = eng.observe_and_evaluate(_events("10.0.1.3", 500, dst_base=200000 + _))["10.0.1.3"]
        alerts += 1 if r.alert else 0
    assert alerts <= 5  # alert_budget


def test_false_positive_feedback_raises_threshold():
    eng = BaselineEngine(_small_config())
    for i in range(70):
        eng.observe_and_evaluate(_events("10.0.1.4", 5, dst_base=i))
    eng.mark_false_positive("10.0.1.4")
    r1 = eng.observe_and_evaluate(_events("10.0.1.4", 200, dst_base=300000))["10.0.1.4"]
    eng2 = BaselineEngine(_small_config())
    for i in range(70):
        eng2.observe_and_evaluate(_events("10.0.1.5", 5, dst_base=i))
    r2 = eng2.observe_and_evaluate(_events("10.0.1.5", 200, dst_base=300000))["10.0.1.5"]
    assert r1.threshold > r2.threshold  # 误报反馈后阈值更宽


def test_high_risk_skips_learning():
    eng = BaselineEngine(_small_config())
    eng.observe_and_evaluate(_events("10.0.1.6", 5), skip_learning=True)
    assert eng._totals["10.0.1.6"] == 0


def test_persistence_roundtrip():
    eng = BaselineEngine(_small_config())
    for i in range(25):
        eng.observe_and_evaluate(_events("10.0.1.7", 5, dst_base=i))
    restored = BaselineEngine.from_dict(eng.to_dict())
    assert restored._totals["10.0.1.7"] == 25
    r = restored.observe_and_evaluate(_events("10.0.1.7", 5))["10.0.1.7"]
    assert r.phase == "shadow" or r.confidence > 0.5


@pytest.mark.asyncio
async def test_pipeline_integration_with_baseline(config, events_ssh_bruteforce):
    """基线引擎并入 aggregate 节点：unit 带 anomaly 字段。"""
    import fakeredis.aioredis

    from app.alerting import AlertStore
    from app.baseline import BaselineEngine
    from app.mcp import MCPClient
    from app.mcp.tools import build_tools
    from app.pipeline.graph import build_graph
    from app.pipeline.nodes import Nodes
    from app.providers import ModelGateway
    from app.providers.base import LLMResponse, Provider
    from app.prompts import PromptBuilder
    from app.rules import RuleEngine
    from app.schemas.keys import session_key
    from app.storage.es_store import ESStore
    from app.storage.redis_store import RedisStore

    class FakeLLM(Provider):
        async def generate(self, messages, tools=None, response_schema=None, max_tokens=512, timeout=60.0):
            return LLMResponse(text='{"risk_level":"medium","verdict":"suspicious","evidence":"x"}')

    redis = RedisStore(fakeredis.aioredis.FakeRedis(decode_responses=True))
    es = ESStore(None)
    engine = RuleEngine(rules_dir="config/rules")
    gateway = ModelGateway(config, {"edge": FakeLLM(config.providers["edge"]), "cloud": FakeLLM(config.providers["cloud"])})  # type: ignore[arg-type]
    mcp = MCPClient(build_tools(es, redis))
    baseline = BaselineEngine(_small_config())
    nodes = Nodes(
        config, redis, es, engine, gateway, mcp, AlertStore(es, dry_run=True),
        PromptBuilder("prompts"), baseline=baseline,
    )
    graph = build_graph(nodes)
    sess = session_key("10.0.0.30", "10.0.0.10", "22", "tcp")
    result = await graph.ainvoke(
        {
            "session_key": sess,
            "events": events_ssh_bruteforce,
            "trace_id": "t-baseline",
            "provider": "edge",
            "messages": [],
            "tool_calls_made": 0,
        }
    )
    unit = result["unit"]
    assert unit.anomaly_phase in ("shadow", "loose", "converged")
    assert unit.anomaly_confidence > 0
    assert unit.anomaly_dimensions or unit.anomaly_score == 0
