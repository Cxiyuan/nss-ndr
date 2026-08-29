"""MCP Client（设计文档 §6.3）：两级发现 + Schema 缓存 + 参数校验 + 结果截断。"""

from __future__ import annotations

from app.mcp.registry import ToolRegistry, truncate_result


class MCPClient:
    """v1 进程内工具调用；后续可替换为 stdio 子进程 MCP Server（协议子集见 stdio_server.py）。"""

    def __init__(self, registry: ToolRegistry, cache: dict[str, dict] | None = None):
        self.registry = registry
        self._schema_cache = cache if cache is not None else registry.schemas()

    def tool_directory(self, groups: list[str] | None = None) -> str:
        """第一级：上下文只注入工具目录。"""
        return self.registry.directory(groups)

    def full_schema(self, name: str) -> dict | None:
        """第二级：完整 Schema 从本地缓存取（不注入上下文）。"""
        return self._schema_cache.get(name)

    def validate(self, name: str, args: dict) -> list[str]:
        return self.registry.validate_args(name, args)

    async def call(self, name: str, args: dict) -> dict:
        return await self.registry.call(name, args)

    def summary(self, result: dict, max_tokens: int = 512) -> str:
        """工具调用结果按需注入且限长（设计文档 §6.5）。"""
        import json

        return json.dumps(truncate_result(result, max_tokens), ensure_ascii=False, default=str)
