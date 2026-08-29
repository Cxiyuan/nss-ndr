"""t-digest 在线分位数草图（设计文档 §14.3）：支持增量更新与跨 worker 合并。"""

from __future__ import annotations

import bisect
from typing import Any


class TDigest:
    """基于质心（centroid）的 t-digest 实现。

    - add(x, w)：增量更新
    - quantile(q)：P5/P50/P95/P99 查询
    - merge(other)：草图合并（多 worker 水平扩展）
    - to_dict / from_dict：Redis 持久化
    """

    def __init__(self, compression: int = 100):
        self.compression = compression
        self.means: list[float] = []
        self.weights: list[float] = []
        self.n: float = 0.0

    def add(self, x: float, w: float = 1.0) -> None:
        if w <= 0:
            return
        self.n += w
        if not self.means:
            self.means.append(float(x))
            self.weights.append(float(w))
            return
        pos = bisect.bisect_left(self.means, x)
        candidates = [i for i in (pos - 1, pos) if 0 <= i < len(self.means)]
        idx = min(candidates, key=lambda i: abs(self.means[i] - x))
        q = self._cum_weight(idx) / self.n
        limit = max(4 * self.n * q * (1 - q) / self.compression, 1.0)
        if self.weights[idx] + w <= limit:
            m, ww = self.means[idx], self.weights[idx]
            self.means[idx] = (m * ww + x * w) / (ww + w)
            self.weights[idx] = ww + w
        else:
            self.means.insert(pos, float(x))
            self.weights.insert(pos, float(w))
        if len(self.means) > self.compression * 10:
            self._compress()

    def _cum_weight(self, idx: int) -> float:
        return sum(self.weights[: idx + 1])

    def _compress(self) -> None:
        order = sorted(range(len(self.means)), key=lambda i: self.means[i])
        means = [self.means[i] for i in order]
        weights = [self.weights[i] for i in order]
        merged_m: list[float] = []
        merged_w: list[float] = []
        i = 0
        total = self.n
        while i < len(means):
            m, w = means[i], weights[i]
            i += 1
            q = (sum(merged_w) + w / 2) / total if total else 0.5
            limit = max(4 * total * q * (1 - q) / self.compression, 1.0)
            while i < len(means) and w + weights[i] <= limit:
                m = (m * w + means[i] * weights[i]) / (w + weights[i])
                w += weights[i]
                i += 1
            merged_m.append(m)
            merged_w.append(w)
        self.means, self.weights = merged_m, merged_w

    def quantile(self, q: float) -> float:
        if self.n <= 0 or not self.means:
            return 0.0
        target = q * self.n
        cum = 0.0
        for i in range(len(self.means)):
            w = self.weights[i]
            if cum + w >= target:
                if i == 0 or w <= 0:
                    return self.means[i]
                frac = (target - cum) / w
                return self.means[i - 1] + (self.means[i] - self.means[i - 1]) * frac
            cum += w
        return self.means[-1]

    def median(self) -> float:
        return self.quantile(0.5)

    def merge(self, other: "TDigest") -> None:
        for m, w in zip(other.means, other.weights):
            self.add(m, w)

    def to_dict(self) -> dict[str, Any]:
        return {
            "compression": self.compression,
            "means": self.means,
            "weights": self.weights,
            "n": self.n,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TDigest":
        t = cls(compression=int(d.get("compression", 100)))
        t.means = [float(x) for x in d.get("means", [])]
        t.weights = [float(w) for w in d.get("weights", [])]
        t.n = float(d.get("n", 0.0))
        return t

    def __repr__(self) -> str:  # pragma: no cover
        return f"TDigest(n={self.n:.0f}, centroids={len(self.means)})"
