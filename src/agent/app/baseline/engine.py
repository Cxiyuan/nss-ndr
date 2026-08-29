"""基线学习与异常检测引擎（设计文档 §14）。

v1 最小闭环：t-digest 分位数基线 + EWMA 双基线 + 三阶段冷启动 + 告警预算 + 反馈闭环。
多窗口（5m/1h/24h）精细滚动聚合、t-digest 跨 worker 合并、节假日日历为后续演进项。
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.baseline.sketches import TDigest
from app.schemas.event import EventEnvelope

FAIL_STATES = {"SF", "REJ", "RST", "S0"}
EPS = 1e-9


@dataclass
class BaselineConfig:
    enabled: bool = True
    learn_min_samples: int = 50      # 阶段一 shadow 结束（0~3 天）
    loose_min_samples: int = 300     # 阶段二 初始基线结束（3~7 天）
    alert_budget: int = 5            # 每实体每日最多告警数（设计文档 §14.5）
    loose_multiplier: float = 2.0    # 阶段二阈值放宽倍数
    alert_threshold: float = 3.0     # 收敛期 z 阈值
    cloud_threshold: float = 6.0     # 升级云端复核阈值
    ewma_alpha: float = 0.3
    truncation_k: float = 3.0        # 抗污染：超过 P99 + k*MAD 的学习降权
    max_samples: int = 20000

    @classmethod
    def from_dict(cls, d: dict | None) -> "BaselineConfig":
        if not d:
            return cls()
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class MetricState:
    digest: TDigest = field(default_factory=TDigest)
    dev_digest: TDigest = field(default_factory=TDigest)  # |x - median| 分布 → MAD
    ewma: float | None = None
    last_value: float | None = None
    samples: int = 0

    def update(self, value: float, cfg: BaselineConfig) -> None:
        if self.samples >= cfg.max_samples:
            return
        median = self.digest.median()
        mad = self.dev_digest.quantile(0.5)
        # 抗污染（设计文档 §14.4）：超出基线上限的观测降权学习
        p99 = self.digest.quantile(0.99)
        weight = 1.0
        if mad > EPS and value > p99 + cfg.truncation_k * mad:
            weight = 0.2
        self.digest.add(value, weight)
        self.dev_digest.add(abs(value - median), weight)
        self.last_value = value
        if self.ewma is None:
            self.ewma = value
        else:
            self.ewma = cfg.ewma_alpha * value + (1 - cfg.ewma_alpha) * self.ewma
        self.samples += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest.to_dict(),
            "dev_digest": self.dev_digest.to_dict(),
            "ewma": self.ewma,
            "last_value": self.last_value,
            "samples": self.samples,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MetricState":
        st = cls()
        st.digest = TDigest.from_dict(d.get("digest", {}))
        st.dev_digest = TDigest.from_dict(d.get("dev_digest", {}))
        st.ewma = d.get("ewma")
        st.last_value = d.get("last_value")
        st.samples = int(d.get("samples", 0))
        return st


@dataclass
class AnomalyResult:
    entity_key: str
    score: float = 0.0
    confidence: float = 0.0
    phase: str = "shadow"          # shadow | loose | converged
    alert: bool = False
    dimensions: dict[str, float] = field(default_factory=dict)
    threshold: float = 0.0


# 观测维度（设计文档 §14.2 子集）：流量/拓扑/服务/应用/质量
METRIC_DEFS: dict[str, str] = {
    "conn_count": "流量-连接数",
    "unique_dst": "拓扑-唯一目标IP",
    "unique_port": "拓扑-唯一端口",
    "failure_ratio": "质量-失败率",
    "dns_count": "应用-DNS查询频次",
    "dns_unique_domain": "应用-唯一域名数",
    "http_count": "应用-HTTP请求频次",
    "http_unique_uri": "应用-唯一URI数",
}


class BaselineEngine:
    """在线统计 + 置信度加权 + 反馈闭环；实体粒度 v1=主机（src_ip）。"""

    def __init__(self, config: BaselineConfig | None = None):
        self.config = config or BaselineConfig()
        self._states: dict[str, dict[str, MetricState]] = defaultdict(dict)
        self._totals: dict[str, int] = defaultdict(int)
        self._daily_alerts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._threshold_multiplier: dict[str, float] = defaultdict(lambda: 1.0)

    # ---- 指标计算 ----
    @staticmethod
    def _metrics(events: list[EventEnvelope]) -> dict[str, float]:
        conns = [e for e in events if e.dataset == "zeek.connection"]
        dnss = [e for e in events if e.dataset == "zeek.dns"]
        https = [e for e in events if e.dataset == "zeek.http"]
        fail = sum(1 for e in conns if (e.enriched or {}).get("conn_state") in FAIL_STATES)
        return {
            "conn_count": float(len(conns)),
            "unique_dst": float(len({e.dst_ip for e in events if e.dst_ip})),
            "unique_port": float(len({e.dst_port for e in events if e.dst_port})),
            "failure_ratio": fail / len(conns) if conns else 0.0,
            "dns_count": float(len(dnss)),
            "dns_unique_domain": float(len({e.enriched.get("query_name") for e in dnss if e.enriched.get("query_name")})),
            "http_count": float(len(https)),
            "http_unique_uri": float(len({e.enriched.get("uri") for e in https if e.enriched.get("uri")})),
        }

    # ---- 学习 + 评估 ----
    def observe_and_evaluate(
        self, events: list[EventEnvelope], skip_learning: bool = False
    ) -> dict[str, AnomalyResult]:
        grouped: dict[str, list[EventEnvelope]] = defaultdict(list)
        for e in events:
            grouped[e.src_ip].append(e)
        results: dict[str, AnomalyResult] = {}
        for ip, evs in grouped.items():
            metrics = self._metrics(evs)
            if not skip_learning:
                states = self._states[ip]
                for m, v in metrics.items():
                    states.setdefault(m, MetricState()).update(v, self.config)
                self._totals[ip] += 1
            results[ip] = self._evaluate(ip, metrics)
        return results

    def _phase(self, total: int) -> str:
        if total < self.config.learn_min_samples:
            return "shadow"
        if total < self.config.loose_min_samples:
            return "loose"
        return "converged"

    def _evaluate(self, ip: str, metrics: dict[str, float]) -> AnomalyResult:
        total = self._totals[ip]
        phase = self._phase(total)
        states = self._states[ip]
        dims: dict[str, float] = {}
        for m, v in metrics.items():
            st = states.get(m)
            if st is None or st.samples == 0:
                continue
            median = st.digest.median()
            mad = st.dev_digest.quantile(0.5)
            if mad <= EPS:
                z = 0.0 if abs(v - median) <= EPS else 4.0
            else:
                z = 0.6745 * (v - median) / mad
            dims[m] = round(z, 3)
        score = max(dims.values(), default=0.0)
        confidence = min(total / max(self.config.learn_min_samples, 1), 1.0)
        multiplier = self.config.loose_multiplier if phase == "loose" else 1.0
        multiplier *= self._threshold_multiplier[ip]
        threshold = self.config.alert_threshold * multiplier
        alert = False
        if phase != "shadow" and score >= threshold and confidence >= 0.5:
            day = time.strftime("%Y-%m-%d")
            if self._daily_alerts[ip][day] < self.config.alert_budget:
                self._daily_alerts[ip][day] += 1
                alert = True
        return AnomalyResult(
            entity_key=ip,
            score=round(score, 3),
            confidence=round(confidence, 3),
            phase=phase,
            alert=alert,
            dimensions=dict(sorted(dims.items(), key=lambda x: -x[1])[:5]),
            threshold=round(threshold, 3),
        )

    # ---- 反馈闭环（设计文档 §14.6）----
    def mark_false_positive(self, ip: str) -> None:
        """误报：该实体阈值放宽（最高 ×5），并降权后续学习。"""
        self._threshold_multiplier[ip] = min(self._threshold_multiplier[ip] * 1.5, 5.0)

    def reset_entity(self, ip: str) -> None:
        self._states.pop(ip, None)
        self._totals.pop(ip, None)
        self._threshold_multiplier.pop(ip, None)

    # ---- 持久化（Redis 草图，支持多 worker 合并）----
    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.__dict__,
            "states": {ip: {m: s.to_dict() for m, s in ms.items()} for ip, ms in self._states.items()},
            "totals": dict(self._totals),
            "multipliers": dict(self._threshold_multiplier),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BaselineEngine":
        eng = cls(BaselineConfig(**d.get("config", {})))
        for ip, ms in (d.get("states") or {}).items():
            for m, s in ms.items():
                eng._states[ip][m] = MetricState.from_dict(s)
        eng._totals.update(d.get("totals") or {})
        eng._threshold_multiplier.update(d.get("multipliers") or {})
        return eng
