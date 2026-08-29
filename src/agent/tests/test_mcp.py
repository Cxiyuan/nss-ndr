import asyncio
import json

import pytest

from app.mcp.registry import ToolRegistry, ToolSpec, truncate_result
from app.mcp.stdio_server import StdioServer


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()

    async def echo(text: str, count: int = 1) -> dict:
        return {"text": text * count}

    reg.register(
        ToolSpec(
            name="echo",
            description="回显文本",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}, "count": {"type": "integer"}},
                "required": ["text"],
            },
            handler=echo,
        )
    )
    return reg


@pytest.mark.asyncio
async def test_validate_args(registry):
    assert registry.validate_args("echo", {"text": "hi"}) == []
    errors = registry.validate_args("echo", {})
    assert any("missing required arg 'text'" in e for e in errors)
    errors = registry.validate_args("echo", {"text": 1})
    assert any("should be string" in e for e in errors)


@pytest.mark.asyncio
async def test_call(registry):
    assert await registry.call("echo", {"text": "ab", "count": 2}) == {"text": "abab"}
    assert "unknown tool" in (await registry.call("nope", {}))["error"]


def test_truncate_result():
    big = {"data": "x" * 5000}
    out = truncate_result(big, max_tokens=100)
    assert out.get("truncated") is True


@pytest.mark.asyncio
async def test_stdio_server(registry):
    server = StdioServer(registry)
    server.reader.feed_data(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode() + b"\n"
    )
    server.reader.feed_eof()
    responses = []

    async def consume():
        async for msg in server:
            responses.append(msg)

    task = asyncio.ensure_future(consume())
    await asyncio.wait_for(task, timeout=5)
    assert responses[0]["result"]["tools"][0]["name"] == "echo"
