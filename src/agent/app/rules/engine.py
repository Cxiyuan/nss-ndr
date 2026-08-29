"""规则引擎（设计文档 §5.5）：声明式规则加载、事件过滤、分组统计、命中评估。"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from app.schemas.analysis import AnalysisUnit, BehaviorHit
from app.schemas.event import EventEnvelope
from app.schemas.keys import session_key

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Rule:
    id: str
    name: str
    attck: str = ""
    input: str = "zeek.connection"
    scope: str = "session"  # session | custom
    aggregate_key: list[str] = field(default_factory=list)
    window: int = 300
    initial_risk: str = "low"
    model: str = "conditional"  # always | never | conditional
    direct_verdict: dict | None = None
    estimated_tool_calls: int = 1
    requires_chain_analysis: bool = False
    match: list[dict] = field(default_factory=list)
    conditions: list[dict] = field(default_factory=list)
    version: str = "1.0"
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _event_dict(event: EventEnvelope, detail: dict | None = None) -> dict:
    """事件扁平化：信封字段 + 富化标签 + ES 回查详情（detail 优先级最高）。"""
    base = event.model_dump(mode="json")
    base.pop("enriched", None)
    base.pop("trace_id", None)
    out: dict[str, Any] = {}
    out.update(base)
    for k, v in (event.enriched or {}).items():
        out[k] = v
    if detail:
        out.update(detail)
    return out


def _op_ok(op: str, actual: Any, expected: Any) -> bool:
    try:
        if op == "eq":
            return _norm(actual) == _norm(expected)
        if op == "ne":
            return _norm(actual) != _norm(expected)
        if op == "in":
            return _norm(actual) in {_norm(x) for x in expected}
        if op in ("gt", "ge", "lt", "le"):
            f = {"gt": lambda a, b: a > b, "ge": lambda a, b: a >= b, "lt": lambda a, b: a < b, "le": lambda a, b: a <= b}[op]
            try:
                return f(float(actual), float(expected))
            except (TypeError, ValueError):
                return False
        if op == "contains":
            return _norm(expected) in _norm(actual)
        if op == "regex":
            return re.search(str(expected), str(actual or "")) is not None
        if op == "exists":
            return actual is not None and str(actual) != ""
    except Exception:
        return False
    return False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s.lower():
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _stat_value(stat: str, rows: list[dict], cond: dict) -> float:
    field = cond.get("field")
    if stat == "count":
        return float(len(rows))
    if stat == "distinct":
        return float(len({_norm(r.get(field)) for r in rows if r.get(field)}))
    if stat in ("sum", "max", "avg"):
        vals = []
        for r in rows:
            try:
                vals.append(float(r.get(field)))
            except (TypeError, ValueError):
                continue
        if not vals:
            return 0.0
        return {"sum": sum, "max": max, "avg": lambda v: sum(v) / len(v)}[stat](vals)
    if stat == "ratio":
        if not rows:
            return 0.0
        expected = {_norm(x) for x in cond.get("in", [cond.get("value", "")])}
        hit = sum(1 for r in rows if _norm(r.get(field)) in expected)
        return hit / len(rows)
    if stat == "failed_ratio":
        if not rows:
            return 0.0
        fail = {_norm(x) for x in cond.get("in", ["SF", "REJ", "RST", "S0"])}
        hit = sum(1 for r in rows if _norm(r.get("conn_state", "")) in fail)
        return hit / len(rows)
    if stat == "high_entropy_ratio":
        if not rows:
            return 0.0
        hit = sum(1 for r in rows if _entropy(str(r.get(field) or "")) > 3.5)
        return hit / len(rows)
    if stat == "distinct_ratio":
        if not rows:
            return 0.0
        distinct = len({_norm(r.get(field)) for r in rows if r.get(field)})
        return distinct / len(rows)
    return 0.0


class RuleEngine:
    """加载 config/rules/*.yaml 并按批次评估命中行为。"""

    def __init__(self, rules: Iterable[Rule] | None = None, rules_dir: str | Path | None = None):
        self.rules: list[Rule] = []
        if rules_dir is not None:
            for path in sorted(Path(rules_dir).glob("*.yaml")):
                self.rules.extend(Rule.from_dict(d) for d in yaml.safe_load(path.read_text(encoding="utf-8")) or [])
        if rules is not None:
            self.rules.extend(rules)
        self.rules = [r for r in self.rules if r.enabled]

    # ---- 事件过滤 ----
    def _matches(self, rule: Rule, ev: dict) -> bool:
        if rule.input and ev.get("dataset") != rule.input:
            return False
        return all(_op_ok(m.get("op", "eq"), ev.get(m["field"]), m.get("value")) for m in rule.match)

    def _group_key(self, rule: Rule, ev: dict) -> tuple[str, ...]:
        if rule.scope == "session":
            return (ev["src_ip"], ev["dst_ip"], ev.get("dst_port") or "", ev.get("proto") or "")
        return tuple(_norm(ev.get(f)) for f in rule.aggregate_key)

    # ---- 批次评估：返回 session_key -> hits ----
    def evaluate(
        self,
        events: list[EventEnvelope],
        details: dict[str, dict] | None = None,
    ) -> dict[str, list[BehaviorHit]]:
        rows = {e.event_id: _event_dict(e, (details or {}).get(e.event_id)) for e in events}
        session_of: dict[str, str] = {}
        for e in events:
            session_of[e.event_id] = session_key(e.src_ip, e.dst_ip, e.dst_port, e.proto)

        hits_by_session: dict[str, list[BehaviorHit]] = defaultdict(list)
        for rule in self.rules:
            matched = [ev for ev in rows.values() if self._matches(rule, ev)]
            if not matched:
                continue
            groups: dict[tuple, list[dict]] = defaultdict(list)
            for ev in matched:
                groups[self._group_key(rule, ev)].append(ev)
            for _gkey, group in groups.items():
                stats = [_stat_value(c.get("stat", "count"), group, c) for c in rule.conditions]
                conds = [
                    _op_ok(c.get("op", "ge"), stats[i], c.get("value"))
                    for i, c in enumerate(rule.conditions)
                ]
                if not all(conds):
                    continue
                hit = BehaviorHit(
                    behavior_id=rule.id,
                    name=rule.name,
                    attck=rule.attck,
                    initial_risk=rule.initial_risk,
                    count=len(group),
                    matched=True,
                )
                # 把命中挂到该组内事件所属的所有会话
                touched_sessions = {session_of[ev["event_id"]] for ev in group if ev.get("event_id") in session_of}
                for sess in touched_sessions:
                    hits_by_session[sess].append(hit)
        return dict(hits_by_session)

    # ---- 组装 analysis_unit（含升级标志）----
    def build_unit(
        self,
        sess: str,
        events: list[EventEnvelope],
        hits: list[BehaviorHit],
    ) -> AnalysisUnit:
        hits = [h for h in hits if h.matched]
        risk = "low"
        for h in hits:
            if RISK_ORDER.get(h.initial_risk, 0) > RISK_ORDER[risk]:
                risk = h.initial_risk

        hit_rules = {r.id: r for r in self.rules}
        est_tools = sum(
            hit_rules.get(h.behavior_id, Rule(id=h.behavior_id, name=h.name)).estimated_tool_calls for h in hits
        )
        requires_chain = any(
            hit_rules.get(h.behavior_id, Rule(id=h.behavior_id, name=h.name)).requires_chain_analysis for h in hits
        )
        # 所有命中均为"规则直接判定"（model=never）时视为已消歧
        rule_resolved = bool(hits) and all(
            hit_rules.get(h.behavior_id, Rule(id=h.behavior_id, name=h.name)).model == "never" for h in hits
        )

        datasets = defaultdict(int)
        ports = set()
        for e in events:
            datasets[e.dataset] += 1
            if e.dst_port:
                ports.add(e.dst_port)
        last_ts = max((e.ts for e in events), default="")
        last_id = events[-1].event_id if events else ""

        return AnalysisUnit(
            session_key=sess,
            events=[e.event_id for e in events],
            event_count=len(events),
            summary={
                "datasets": dict(datasets),
                "dst_ports": sorted(ports)[:20],
                "behavior_hits": [h.behavior_id for h in hits],
            },
            behavior_hits=hits,
            initial_risk=risk,
            estimated_tool_calls=min(est_tools, 9),
            requires_chain_analysis=requires_chain,
            rule_resolved=rule_resolved,
            watermark={"last_event_id": last_id, "last_ts": last_ts, "event_count": len(events)},
        )
