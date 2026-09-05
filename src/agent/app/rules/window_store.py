"""规则滚动窗口存储(Phase D1):把规则窗口事件跨批累积在 Redis,支撑分布式低频行为命中。

背景(见 docs/research/phase-c-observation-2026-09-05.md §3 F1):
旧版 RuleEngine.evaluate 只对"单个 5s 批内、同一会话组"的事件求值,Rule.window(秒)
从未跨批生效 —— BEH-001(SMB 爆破 src→≥3 dst:445/300s)、BEH-002(DNS 隧道)这类
低频分布式攻击在单批内通常只有 0-1 条事件,永远凑不齐 condition,behavior_hits 恒空。

本模块提供 Redis 键布局:
  rw:z:{rule_id}:{group_key}    ZSET  member=event_id  score=事件到达时间戳(ms)
  rw:ev:{event_id}              STRING 扁平事件 JSON(EX=window+margin)

语义:
- 只对"本批新增事件所在的分组"做窗口累积与重评 —— 无更新的分组不会重复触发;
- 惰性剪枝:取窗口时 ZREMRANGEBYSCORE 清理过期成员;payload 由 TTL 自然回收;
- 每分组最多保留 max_rows_per_group 条(防高频源撑爆内存)。
"""
from __future__ import annotations

import json
import time
from typing import Any

# 分组键内部连接符(避免 IP/端口中出现 \x1f 造成歧义,实际值几乎不可能包含)
_GROUP_SEP = "\x1f"


def group_key_str(parts: tuple[Any, ...]) -> str:
    """把规则分组键(aggregate_key 值或会话四元组)归一化为稳定字符串。"""
    return _GROUP_SEP.join(str(p).strip().lower() for p in parts)


class RuleWindowStore:
    def __init__(self, client: Any, margin_seconds: int = 600, max_rows_per_group: int = 500):
        self.client = client
        self.margin = margin_seconds
        self.max_rows = max_rows_per_group

    @staticmethod
    def _zkey(rule_id: str, group_key: str) -> str:
        return f"rw:z:{rule_id}:{group_key}"

    @staticmethod
    def _vkey(event_id: str) -> str:
        return f"rw:ev:{event_id}"

    async def add(
        self,
        rule_id: str,
        group_key: str,
        rows: list[dict],
        window_seconds: int,
        now_ms: int | None = None,
    ) -> None:
        """把本批命中规则的事件写入该分组的滚动窗口(幂等:同 event_id 覆写 score)。"""
        if not rows:
            return
        now_ms = int(now_ms) if now_ms is not None else int(time.time() * 1000)
        expire = int(window_seconds) + self.margin
        zkey = self._zkey(rule_id, group_key)
        pipe = self.client.pipeline(transaction=False)
        for row in rows:
            eid = str(row.get("event_id") or "")
            if not eid:
                continue
            pipe.zadd(zkey, {eid: now_ms})
            pipe.set(self._vkey(eid), json.dumps(row, ensure_ascii=False), ex=expire)
        # 只保留最近 max_rows(rank 0 起删最旧)
        pipe.zremrangebyrank(zkey, 0, -self.max_rows - 1)
        pipe.expire(zkey, expire)
        await pipe.execute()

    async def window_rows(
        self,
        rule_id: str,
        group_key: str,
        window_seconds: int,
        now_ms: int | None = None,
    ) -> list[dict]:
        """返回该分组在滚动窗口内的全部扁平事件(含刚写入的本批事件)。"""
        now_ms = int(now_ms) if now_ms is not None else int(time.time() * 1000)
        since = now_ms - int(window_seconds) * 1000
        zkey = self._zkey(rule_id, group_key)
        ids = await self.client.zrangebyscore(zkey, since, "+inf")
        # 惰性剪枝:清掉窗口外过期成员
        await self.client.zremrangebyscore(zkey, "-inf", since)
        if not ids:
            return []
        ids = ids[-self.max_rows:]
        raw = await self.client.mget([self._vkey(i) for i in ids])
        out: list[dict] = []
        missing: list[str] = []
        for eid, val in zip(ids, raw):
            if not val:
                missing.append(eid)
                continue
            try:
                out.append(json.loads(val))
            except (ValueError, TypeError):
                missing.append(eid)
        if missing:
            await self.client.zrem(zkey, *missing)
        return out
