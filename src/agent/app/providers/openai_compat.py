"""OpenAI 兼容 Provider（llama-server / 云端模型均适用）。"""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from app.providers.base import LLMResponse, Provider, ToolCall


class OpenAICompatProvider(Provider):
    """通过 httpx 直连 OpenAI 兼容 /chat/completions。"""

    def __init__(self, config, client: httpx.AsyncClient | None = None):
        super().__init__(config)
        self._http = client or httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=httpx.Timeout(60.0),
            headers={"Authorization": f"Bearer {config.api_key}"} if config.api_key else {},
        )

    async def close(self) -> None:
        await self._http.aclose()

    def _payload(
        self,
        messages: list[dict],
        tools: list[dict] | None,
        response_schema: dict | None,
        max_tokens: int,
        stream: bool = False,
    ) -> dict:
        payload: dict = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.1,
            "stream": stream,
        }
        if tools and self.config.capabilities.get("tool_calling"):
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if response_schema and self.config.capabilities.get("json_schema"):
            payload["response_format"] = {"type": "json_object", "schema": response_schema}
        return payload

    @staticmethod
    def _parse_choice(choice: dict) -> LLMResponse:
        msg = choice.get("message") or {}
        text = msg.get("content") or ""
        calls = []
        for tc in msg.get("tool_calls") or []:
            args = tc.get("function", {}).get("arguments") or "{}"
            try:
                arguments = json.loads(args) if isinstance(args, str) else args
            except json.JSONDecodeError:
                arguments = {"_raw": args}
            calls.append(
                ToolCall(
                    id=tc.get("id", ""),
                    name=tc.get("function", {}).get("name", ""),
                    arguments=arguments,
                )
            )
        return LLMResponse(text=text or "", tool_calls=calls, raw=choice)

    async def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        response_schema: dict | None = None,
        max_tokens: int = 512,
        timeout: float = 60.0,
    ) -> LLMResponse:
        payload = self._payload(messages, tools, response_schema, max_tokens)
        try:
            resp = await self._http.post("/chat/completions", json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            return LLMResponse(error=f"{type(e).__name__}: {e}")
        choices = data.get("choices") or []
        if not choices:
            return LLMResponse(error=f"empty choices: {data}")
        return self._parse_choice(choices[0])

    async def stream(self, messages: list[dict], tools: list[dict] | None = None) -> AsyncIterator[str]:
        payload = self._payload(messages, tools, None, 512, stream=True)
        async with self._http.stream("POST", "/chat/completions", json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    delta = json.loads(chunk)["choices"][0].get("delta", {})
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue
                if delta.get("content"):
                    yield delta["content"]
