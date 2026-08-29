"""LLM Provider 抽象（设计文档 §15.2）：OpenAI 兼容接口 + 能力声明。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator

from app.config import ProviderConfig


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


class Provider(ABC):
    """所有 Provider 统一接口；智能体不感知底层是本地边缘还是云端。"""

    def __init__(self, config: ProviderConfig):
        self.config = config

    @abstractmethod
    async def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        response_schema: dict | None = None,
        max_tokens: int = 512,
        timeout: float = 60.0,
    ) -> LLMResponse:
        ...

    async def stream(self, messages: list[dict], tools: list[dict] | None = None) -> AsyncIterator[str]:
        """默认不支持流式；支持流式的 Provider 覆写。"""
        yield ""

    def estimate_tokens(self, messages: list[dict]) -> int:
        """粗略估算：约 4 字符/token，中文按 1.5 字符/token。"""
        total = 0
        for m in messages:
            content = str(m.get("content") or m.get("text") or "")
            total += int(len(content) / 2.0)
            if m.get("role") == "system":
                total += 32
        return max(total, 1)

    def get_metadata(self) -> dict:
        return {
            "name": self.config.name,
            "model": self.config.model,
            "max_context": self.config.max_context,
            "capabilities": self.config.capabilities,
        }
