import httpx
import pytest

from app.config import ProviderConfig
from app.providers import ModelGateway, needs_cloud
from app.providers.openai_compat import OpenAICompatProvider


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (dict(initial_risk="high"), True),
        (dict(local_risk="high"), True),
        (dict(requires_chain_analysis=True), True),
        (dict(behavior_hits=2, rule_resolved=False), True),
        (dict(behavior_hits=2, rule_resolved=True), False),
        (dict(local_verdict="uncertain"), True),
        (dict(estimated_tool_calls=3), True),
        (dict(anomaly_alert=True), True),
        (dict(initial_risk="medium", behavior_hits=1, estimated_tool_calls=1), False),
    ],
)
def test_needs_cloud(kwargs, expected):
    assert needs_cloud(**kwargs) is expected


@pytest.mark.asyncio
async def test_openai_compat_provider_tool_call():
    def handler(request: httpx.Request) -> httpx.Response:
        body = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "function": {
                                    "name": "query_peer_relations",
                                    "arguments": '{"ip": "10.0.0.1", "time_range": "1h"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
        return httpx.Response(200, json=body)

    transport = httpx.MockTransport(handler)
    cfg = ProviderConfig(name="edge", base_url="http://llm", api_key="k", model="xlam")
    provider = OpenAICompatProvider(cfg, client=httpx.AsyncClient(transport=transport, base_url="http://llm"))
    resp = await provider.generate([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert resp.ok
    assert resp.tool_calls[0].name == "query_peer_relations"
    assert resp.tool_calls[0].arguments["ip"] == "10.0.0.1"
    await provider.close()


@pytest.mark.asyncio
async def test_gateway_circuit_breaker(config):
    edge_cfg = config.providers["edge"]

    class FailingProvider:
        name = "edge"
        config = edge_cfg

        def estimate_tokens(self, messages):
            return 10

        async def generate(self, messages, tools=None, response_schema=None, max_tokens=512, timeout=60.0):
            from app.providers.base import LLMResponse

            return LLMResponse(error="boom")

    gateway = ModelGateway(config, {"edge": FailingProvider()})  # type: ignore[arg-type]
    for _ in range(6):
        resp = await gateway.generate("edge", [{"role": "user", "content": "x"}])
    # 超过连续失败阈值后熔断
    resp = await gateway.generate("edge", [{"role": "user", "content": "x"}])
    assert "circuit open" in resp.error
