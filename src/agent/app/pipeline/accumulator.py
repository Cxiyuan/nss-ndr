"""跨批会话累积(P3,2026-09-05 输入重心)。

背景(docs/research/agent-input-format-v2-2026-09-05.md §P3):worker 原按 5s 批切分
会话 → 长连接/爆破序列被切成"批内片段",每片段独立判定、event_count 很小,模型拿不到
完整上下文,只能靠 es_search 自行跨会话拼装。

本模块把同 (src_ip, dst_ip, dst_port) 的事件跨批累积为"情节(episode)"。满足任一
flush 条件即把整段交给会话分析(flush 时做 proto 回填,再按 session_key 分组子会话):
  - 空闲:距该情节最后一个事件 ≥ flush_idle 秒(流结束/暂停)
  - 事件数 ≥ max_events(毒丸上限,防广播等无界会话)
  - 存活 ≥ max_age(慢速流兜底)
  - 累积情节数 ≥ max_sessions(内存兜底,flush 最旧)

可靠性:事件在 flush 前**不 ack、不打 evt 标记** → 崩溃后由 XAUTOCLAIM 重投重建同一
情节,不丢不重;单 worker 进程内累积,重启丢内存由重投补偿。事件级与 entry 级双去重
(同 event_id 只存一次,同 entry_id 只记一次待 ack)。
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 情节键:与 proto 无关,flush 时才解析 proto 分组(整情节内 conn 行可回填 ssh/weird)
EpisodeKey = tuple[str, str, str]


@dataclass
class _Episode:
    key: EpisodeKey
    events: list = field(default_factory=list)      # EventEnvelope
    event_ids: set = field(default_factory=set)     # 去重
    entry_ids: list = field(default_factory=list)   # 待 ack 的 stream entry id(去重后)
    entry_set: set = field(default_factory=set)
    first_ts: float = 0.0
    last_ts: float = 0.0
    count: int = 0


class EpisodeAccumulator:
    def __init__(
        self,
        flush_idle: float = 12.0,
        max_events: int = 200,
        max_age: float = 300.0,
        max_sessions: int = 300,
    ):
        self.flush_idle = flush_idle
        self.max_events = max_events
        self.max_age = max_age
        self.max_sessions = max_sessions
        self._buf: dict[EpisodeKey, _Episode] = {}
        self._order: list[EpisodeKey] = []  # FIFO,内存压力时 flush 最旧

    # ---- 查询 ----
    def pending_keys(self) -> list[EpisodeKey]:
        return list(self._buf.keys())

    def pending_events(self) -> int:
        return sum(ep.count for ep in self._buf.values())

    def __len__(self) -> int:
        return len(self._buf)

    # ---- 累积 ----
    def add(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: str,
        event,
        entry_id: str,
        now: float,
    ) -> None:
        key = (src_ip, dst_ip, dst_port or "*")
        ep = self._buf.get(key)
        if ep is None:
            ep = _Episode(key=key, first_ts=now, last_ts=now)
            self._buf[key] = ep
            self._order.append(key)
        # entry 级去重(重投的同一 entry id 不再重复记录待 ack)
        if entry_id and entry_id not in ep.entry_set:
            ep.entry_set.add(entry_id)
            ep.entry_ids.append(entry_id)
        # 事件级去重(同 event_id 只存一次,防 claim 重投重复累积)
        if event.event_id not in ep.event_ids:
            ep.event_ids.add(event.event_id)
            ep.events.append(event)
            ep.count += 1
            ep.last_ts = now

    # ---- flush 判定 ----
    def ripe_keys(self, now: float) -> list[EpisodeKey]:
        """满足任一 flush 条件的情节键。"""
        out: list[EpisodeKey] = []
        for key, ep in list(self._buf.items()):
            idle = now - ep.last_ts
            age = now - ep.first_ts
            if (
                idle >= self.flush_idle
                or ep.count >= self.max_events
                or age >= self.max_age
            ):
                out.append(key)
        # 内存压力:超出上限 flush 最旧(按 last_ts)
        if len(self._buf) > self.max_sessions:
            extra = len(self._buf) - self.max_sessions
            oldest = sorted(self._buf.items(), key=lambda kv: kv[1].last_ts)[:extra]
            for key, _ in oldest:
                if key not in out:
                    out.append(key)
        return out

    def pop(self, key: EpisodeKey) -> tuple[list, list]:
        """取出情节的 (events, entry_ids) 并移除。"""
        ep = self._buf.pop(key, None)
        if ep is None:
            return [], []
        try:
            self._order.remove(key)
        except ValueError:
            pass
        return ep.events, ep.entry_ids
