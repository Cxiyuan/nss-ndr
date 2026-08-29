"""Redis 存储：Streams 消费组 + 缓存/水位/锁/实体画像。"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import redis.asyncio as aioredis

from app.schemas.keys import (
    agent_entity_key,
    agent_result_key,
    evt_key,
    lock_key,
)
from app.storage.lua import (
    ACQUIRE_LOCK_LUA,
    RELEASE_LOCK_LUA,
    SEEN_EVENT_LUA,
    WRITE_VERDICT_LUA,
)


class RedisStore:
    """数据总线 Redis 的智能体侧封装。客户端可注入（测试用 fakeredis）。"""

    def __init__(
        self,
        client: aioredis.Redis,
        stream: str = "analysis:events",
        consumer_group: str = "analysis-group",
        consumer_name: str = "agent-worker",
        result_ttl: int = 3600,
        evt_ttl: int = 86400,
        entity_ttl: int = 86400,
        lock_ttl: int = 30,
    ):
        self.client = client
        self.stream = stream
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name
        self.result_ttl = result_ttl
        self.evt_ttl = evt_ttl
        self.entity_ttl = entity_ttl
        self.lock_ttl = lock_ttl
    async def _eval(self, source: str, keys: list[str], args: list) -> Any:
        """EVAL 直接执行 Lua（兼容 fakeredis；EVALSHA 在部分环境不支持）。"""
        return await self.client.eval(source, len(keys), *(keys + args))

    async def ping(self) -> bool:
        try:
            return bool(await self.client.ping())
        except Exception:
            return False

    # ---- Streams 消费组 ----
    async def ensure_group(self) -> None:
        """创建 Stream 消费组；Stream 不存在时用空流兜底，避免 XGROUP CREATE 报错。"""
        try:
            await self.client.xgroup_create(self.stream, self.consumer_group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def read_batch(self, count: int, block_ms: int) -> list[tuple[str, dict]]:
        """按消费组批量拉取：返回 [(entry_id, fields), ...]。"""
        raw = await self.client.xreadgroup(
            self.consumer_group,
            self.consumer_name,
            {self.stream: ">"},
            count=count,
            block=block_ms,
        )
        out: list[tuple[str, dict]] = []
        for _stream, entries in raw or []:
            for entry_id, fields in entries:
                out.append((entry_id.decode() if isinstance(entry_id, bytes) else entry_id, fields))
        return out

    async def ack(self, entry_ids: list[str]) -> None:
        if entry_ids:
            await self.client.xack(self.stream, self.consumer_group, *entry_ids)

    async def claim_stale(self, min_idle_ms: int = 60000, max_claims: int = 200) -> list[tuple[str, dict]]:
        """XAUTOCLAIM：崩溃 worker 遗留的滞留消息重投给本 worker（设计文档 §3）。"""
        try:
            raw = await self.client.xautoclaim(
                self.stream, self.consumer_group, self.consumer_name, min_idle_ms, "0", count=max_claims
            )
            _, entries, _ = raw
            return [(eid.decode() if isinstance(eid, bytes) else eid, fields) for eid, fields in (entries or [])]
        except aioredis.ResponseError:
            return []

    # ---- 幂等 / 锁 ----
    async def mark_event_seen(self, event_id: str) -> bool:
        """事件级水位：evt:{event_id} SETNX TTL。返回 True=首次（需处理）。"""
        return bool(await self._eval(SEEN_EVENT_LUA, [evt_key(event_id)], [self.evt_ttl]))

    async def acquire_lock(self, sess: str) -> str | None:
        token = uuid.uuid4().hex
        ok = await self._eval(ACQUIRE_LOCK_LUA, [lock_key(sess)], [token, self.lock_ttl])
        return token if ok else None

    async def release_lock(self, sess: str, token: str) -> None:
        await self._eval(RELEASE_LOCK_LUA, [lock_key(sess)], [token])

    # ---- 结论 / 水位 ----
    async def get_result(self, sess: str) -> dict | None:
        raw = await self.client.get(agent_result_key(sess))
        return json.loads(raw) if raw else None

    async def write_verdict(self, sess: str, verdict_json: str, ttl: int | None = None) -> str:
        """Lua 原子写回结论（含 watermark），返回旧值。"""
        old = await self._eval(WRITE_VERDICT_LUA, [agent_result_key(sess)], [verdict_json, ttl or self.result_ttl])
        return old.decode() if isinstance(old, bytes) else str(old)

    # ---- 实体画像（设计文档 §4.2）----
    async def get_entity(self, ip: str) -> list[dict]:
        raw = await self.client.get(agent_entity_key(ip))
        return json.loads(raw) if raw else []

    async def append_entity(self, ip: str, entry: dict, max_entries: int = 50) -> None:
        """实体画像滚动窗口：保留最近 N 条行为摘要（每条 ≤100 tokens 由调用方保证）。"""
        current = await self.get_entity(ip)
        current.append(entry)
        trimmed = current[-max_entries:]
        await self.client.set(agent_entity_key(ip), json.dumps(trimmed), ex=self.entity_ttl)

    # ---- 缓存主动失效（设计文档 §3：资产/提示词变更时联动）----
    async def invalidate_prefix(self, prefix: str) -> int:
        keys = [k async for k in self.client.scan_iter(match=f"{prefix}*")]
        if keys:
            return await self.client.delete(*keys)
        return 0


def timestamp_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
