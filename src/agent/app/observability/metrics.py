"""指标分层（设计文档 §12.3）：管道/分析/业务/成本。v1 进程内字典 + Prometheus 可选。"""

from __future__ import annotations

import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Iterator


class Metrics:
    def __init__(self):
        self.counters: dict[str, int] = defaultdict(int)
        self.timings: dict[str, list[float]] = defaultdict(list)

    def inc(self, name: str, by: int = 1) -> None:
        self.counters[name] += by

    def observe(self, name: str, seconds: float) -> None:
        self.timings[name].append(seconds)
        if len(self.timings[name]) > 1000:
            self.timings[name] = self.timings[name][-1000:]

    @contextmanager
    def time(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - start)

    def snapshot(self) -> dict:
        out = dict(self.counters)
        for name, vals in self.timings.items():
            if vals:
                vals_sorted = sorted(vals)
                n = len(vals_sorted)
                out[f"{name}_p50"] = vals_sorted[n // 2]
                out[f"{name}_p95"] = vals_sorted[min(n - 1, int(n * 0.95))]
                out[f"{name}_p99"] = vals_sorted[min(n - 1, int(n * 0.99))]
        return out

    def render_prometheus(self) -> str:
        lines = []
        for k, v in self.counters.items():
            lines.append(f"nss_ndr_agent_{k.replace('.', '_')} {v}")
        for k, v in self.timings.items():
            if v:
                lines.append(f"nss_ndr_agent_{k.replace('.', '_')}_count {len(v)}")
        return "\n".join(lines) + "\n"
