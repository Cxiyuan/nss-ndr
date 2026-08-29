"""MCP over stdio 服务端（JSON-RPC 子集）。

供后续"每个后端服务独立 MCP Server 子进程"使用；v1 管线直接走 ToolRegistry，
本适配器保留协议兼容：initialize / tools/list / tools/call。
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import AsyncIterator

from app.mcp.registry import ToolRegistry


class StdioServer:
    def __init__(self, registry: ToolRegistry, reader: asyncio.StreamReader | None = None, writer: asyncio.StreamWriter | None = None):
        self.registry = registry
        self.reader = reader or asyncio.StreamReader()
        self.writer = writer

    async def _handle(self, msg: dict) -> dict:
        method = msg.get("method")
        rid = msg.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "nss-ndr-agent-mcp", "version": "0.1.0"}}}
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": [
                        {"name": s.name, "description": s.description, "inputSchema": s.parameters}
                        for s in self.registry.list_specs()
                    ]
                },
            }
        if method == "tools/call":
            params = msg.get("params") or {}
            result = await self.registry.call(params.get("name", ""), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}

    async def serve(self) -> None:
        while True:
            line = await self.reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = await self._handle(msg)
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    async def __aiter__(self) -> AsyncIterator[dict]:
        """测试用：按行产出请求并收集响应。"""
        while True:
            line = await self.reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield await self._handle(msg)
