"""trace_id 贯穿（设计文档 §12.3）。"""

from __future__ import annotations

import contextvars
import uuid


class TraceContext:
    _current: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

    @classmethod
    def get(cls) -> str:
        return cls._current.get()

    @classmethod
    def set(cls, trace_id: str | None = None) -> str:
        tid = trace_id or uuid.uuid4().hex[:16]
        cls._current.set(tid)
        return tid

    @classmethod
    def reset(cls) -> None:
        cls._current.set("")
