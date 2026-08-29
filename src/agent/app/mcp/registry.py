"""MCP 工具注册表：Schema 集中定义 + 参数校验 + 执行。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON Schema
    handler: Callable[..., Awaitable[dict]]
    group: str = "network"  # 场景分组（设计文档 §6.5：超 15 个工具按场景注入）
    max_result_tokens: int = 512

    @property
    def openai_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    @property
    def one_line(self) -> str:
        """工具目录条目：上下文只注入"名称 + 一句话用途"（设计文档 §6.2）。"""
        return f"- {self.name}：{self.description}"


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_specs(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def openai_tools(self, group: str | None = None) -> list[dict]:
        specs = [s for s in self._tools.values() if group is None or s.group == group]
        return [s.openai_schema for s in specs]

    def directory(self, groups: list[str] | None = None) -> str:
        """工具目录文本：常驻系统提示词，~150-250 tokens。"""
        specs = [s for s in self._tools.values() if groups is None or s.group in groups]
        return "可用工具：\n" + "\n".join(s.one_line for s in specs)

    def schemas(self) -> dict[str, dict]:
        """完整 Schema 本地缓存（不进上下文，调用时补全）。"""
        return {name: s.parameters for name, s in self._tools.items()}

    def validate_args(self, name: str, args: dict) -> list[str]:
        """Client 侧强校验：必填字段 + 基础类型（设计文档 §6.3）。"""
        spec = self._tools.get(name)
        if spec is None:
            return [f"unknown tool: {name}"]
        errors: list[str] = []
        schema = spec.parameters
        required = schema.get("required", [])
        props = schema.get("properties", {})
        for key in required:
            if key not in args or args[key] in (None, ""):
                errors.append(f"{name}: missing required arg '{key}'")
        for key, value in args.items():
            prop = props.get(key)
            if prop is None:
                continue
            expected = prop.get("type")
            if expected == "string" and not isinstance(value, str):
                errors.append(f"{name}: arg '{key}' should be string")
            elif expected == "integer" and not isinstance(value, int):
                errors.append(f"{name}: arg '{key}' should be integer")
            elif expected == "array" and not isinstance(value, list):
                errors.append(f"{name}: arg '{key}' should be array")
        return errors

    async def call(self, name: str, args: dict) -> dict:
        spec = self._tools.get(name)
        if spec is None:
            return {"error": f"unknown tool: {name}"}
        errors = self.validate_args(name, args)
        if errors:
            return {"error": "; ".join(errors)}
        try:
            result = await spec.handler(**args)
            return truncate_result(result, spec.max_result_tokens)
        except Exception as e:  # noqa: BLE001
            return {"error": f"{name} failed: {type(e).__name__}: {e}"}


def truncate_result(result: dict, max_tokens: int = 512) -> dict:
    """结果截断 ≤ max_tokens（约 2 字符/token 估算），避免撑爆上下文。"""
    text = json.dumps(result, ensure_ascii=False, default=str)
    limit = max_tokens * 2
    if len(text) <= limit:
        return result
    truncated = text[:limit] + ',"truncated":true}'
    try:
        return json.loads(truncated)
    except json.JSONDecodeError:
        return {"truncated": True, "preview": text[:limit]}
