import json

import fakeredis.aioredis
import pytest

from app.alerting import AlertStore
from app.assets import AssetKB
from app.config import AgentConfig
from app.mcp import MCPClient
from app.mcp.tools import build_tools
from app.pipeline.graph import build_graph
from app.pipeline.nodes import Nodes
from app.providers import ModelGateway
from app.providers.base import LLMResponse, Provider
from app.prompts import PromptBuilder
from app.rules import RuleEngine
from app.schemas.event import EventEnvelope
from app.schemas.keys import session_key
from app.storage.es_store import ESStore
from app.storage.redis_store import RedisStore


class FakeLLM(Provider):
    def __init__(self, config, response_text: str):
        super().__init__(config)
        self.response_text = response_text

    async def generate(self, messages, tools=None, response_schema=None, max_tokens=512, timeout=60.0):
        return LLMResponse(text=self.response_text)


def build_env(config: AgentConfig, llm_text: str = ""):
    redis = RedisStore(fakeredis.aioredis.FakeRedis(decode_responses=True))
    es = ESStore(None)  # client=None：写操作 noop
    engine = RuleEngine(rules_dir="config/rules")
    providers = {
        "edge": FakeLLM(config.providers["edge"], llm_text or '{"risk_level":"medium","verdict":"ssh_bruteforce_suspected","evidence":"25 conns to :22, 50% failed","suggest_action":"封禁源IP"}'),
        "cloud": FakeLLM(config.providers["cloud"], '{"risk_level":"high","verdict":"confirmed_bruteforce","evidence":"cloud review","suggest_action":"隔离主机"}'),
    }
    gateway = ModelGateway(config, providers)  # type: ignore[arg-type]
    mcp = MCPClient(build_tools(es, redis))
    alerts = AlertStore(es, dry_run=True)
    nodes = Nodes(config, redis, es, engine, gateway, mcp, alerts, PromptBuilder("prompts"))
    graph = build_graph(nodes)
    return graph, redis, es


@pytest.mark.asyncio
async def test_pipeline_model_path(config, events_ssh_bruteforce):
    graph, redis, es = build_env(config)
    sess = session_key("10.0.0.30", "10.0.0.10", "22", "tcp")
    result = await graph.ainvoke(
        {
            "session_key": sess,
            "events": events_ssh_bruteforce,
            "trace_id": "t1",
            "provider": "edge",
            "messages": [],
            "tool_calls_made": 0,
        }
    )
    assert result["final"] is not None
    assert result["final"].verdict == "ssh_bruteforce_suspected"
    assert result["final"].risk_level == "medium"
    # Redis 已写回
    cached = await redis.get_result(sess)
    assert cached["verdict"] == "ssh_bruteforce_suspected"


@pytest.mark.asyncio
async def test_pipeline_cache_hit(config, events_ssh_bruteforce):
    graph, redis, es = build_env(config)
    sess = session_key("10.0.0.30", "10.0.0.10", "22", "tcp")
    await redis.write_verdict(
        sess,
        json.dumps({"verdict": "old", "watermark": {"last_ts": "2026-08-29T11:00:00Z", "event_count": 25}}),
    )
    result = await graph.ainvoke(
        {
            "session_key": sess,
            "events": events_ssh_bruteforce,
            "trace_id": "t2",
            "provider": "edge",
            "messages": [],
            "tool_calls_made": 0,
        }
    )
    assert result.get("reused") is True
    assert result.get("final") is None


@pytest.mark.asyncio
async def test_pipeline_escalate_to_cloud(config, events_ssh_bruteforce):
    # 本地模型输出 high → 升级云端
    graph, redis, es = build_env(config, llm_text='{"risk_level":"high","verdict":"suspicious","evidence":"local"}')
    sess = session_key("10.0.0.30", "10.0.0.10", "22", "tcp")
    result = await graph.ainvoke(
        {
            "session_key": sess,
            "events": events_ssh_bruteforce,
            "trace_id": "t3",
            "provider": "edge",
            "messages": [],
            "tool_calls_made": 0,
        }
    )
    assert result["final"].verdict == "confirmed_bruteforce"
    assert result["final"].model.startswith("cloud:")


@pytest.mark.asyncio
async def test_pipeline_rule_direct_path(config):
    # BEH-005 端口扫描：规则直接判定，不调用模型
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
    graph, redis, es = build_env(config)
    sess = session_key("10.0.0.99", "10.0.0.50", "1000", "tcp")
    result = await graph.ainvoke(
        {
            "session_key": sess,
            "events": events,
            "trace_id": "t4",
            "provider": "edge",
            "messages": [],
            "tool_calls_made": 0,
        }
    )
    assert result["final"].model == "rule-engine"
    assert result["final"].verdict == "benign"  # 规则低危直接判定
