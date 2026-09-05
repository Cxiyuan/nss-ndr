"""LangGraph 节点实现（设计文档 §9.3）。"""

from __future__ import annotations

import json
import re
from typing import Any

from app.alerting import AlertStore
from app.config import AgentConfig
from app.mcp import MCPClient
from app.providers import ModelGateway
from app.rules import RuleEngine
from app.schemas.analysis import AnalysisUnit
from app.schemas.event import EventEnvelope
from app.schemas.keys import alert_fingerprint
from app.schemas.verdict import Verdict
from app.storage.es_store import ESStore
from app.storage.redis_store import RedisStore, timestamp_now


def parse_verdict_text(text: str) -> dict | None:
    """从模型输出解析 JSON 结论：优先整体 JSON，其次取代码块/首个 {…}。"""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _event_watermark(events: list[EventEnvelope]) -> dict:
    last_ts = max((e.ts for e in events), default="")
    return {"last_ts": last_ts, "event_count": len(events)}


class Nodes:
    """节点集合：依赖注入 stores / engine / gateway / mcp / alerting。"""

    def __init__(
        self,
        config: AgentConfig,
        redis: RedisStore,
        es: ESStore,
        engine: RuleEngine,
        gateway: ModelGateway,
        mcp: MCPClient,
        alerts: AlertStore,
        prompt_builder: Any = None,
        baseline: Any = None,
    ):
        self.config = config
        self.redis = redis
        self.es = es
        self.engine = engine
        self.gateway = gateway
        self.mcp = mcp
        self.alerts = alerts
        self.prompt_builder = prompt_builder
        self.baseline = baseline

    # ---- 节点 ----
    async def cache_lookup(self, state: dict) -> dict:
        sess = state["session_key"]
        events = state["events"]
        cached_raw = await self.redis.get_result(sess)
        cached = Verdict(**cached_raw) if cached_raw else None
        wm = _event_watermark(events)
        hit = False
        if cached is not None and cached.watermark:
            cwm = cached.watermark
            if wm.get("last_ts") and cwm.get("last_ts") and cwm["last_ts"] >= wm["last_ts"]:
                if cwm.get("event_count", 0) >= wm.get("event_count", 0):
                    hit = True
        if hit:
            return {"cached": cached, "reused": True}
        return {"cached": cached, "reused": False}

    async def aggregate(self, state: dict) -> dict:
        events = state["events"]
        hits = await self.engine.evaluate_windowed(events)
        sess = state["session_key"]
        unit = self.engine.build_unit(sess, events, hits.get(sess, []))
        # 基线/异常检测并入 aggregate（设计文档 §14.7）：High 时段跳过学习（抗污染）
        if self.baseline is not None and events:
            results = self.baseline.observe_and_evaluate(events, skip_learning=unit.initial_risk == "high")
            res = results.get(events[0].src_ip)
            if res is not None:
                unit.anomaly_score = res.score
                unit.anomaly_confidence = res.confidence
                unit.anomaly_dimensions = list(res.dimensions.keys())
                unit.anomaly_phase = res.phase
                unit.anomaly_alert = res.alert
        return {"unit": unit}

    async def model(self, state: dict) -> dict:
        unit: AnalysisUnit = state["unit"]
        provider = state.get("provider") or self.config.default_provider
        messages = list(state.get("messages") or [])
        if not messages:
            messages = (
                self.prompt_builder.build(
                    unit,
                    state.get("asset_context", ""),
                    self.mcp.tool_directory(),
                    state.get("skill", ""),
                )
                if self.prompt_builder
                else self._default_messages(unit)
            )
        tools = self.mcp.registry.openai_tools()
        resp = await self.gateway.generate(
            provider, messages, tools=tools, response_schema=verdict_schema(), max_tokens=self.config.max_output_tokens
        )
        messages.append({"role": "assistant", "content": resp.text, "tool_calls": [_tc_dict(t) for t in resp.tool_calls]})
        out: dict = {"messages": messages, "provider": provider}
        if resp.tool_calls:
            out["tool_calls_made"] = state.get("tool_calls_made", 0) + len(resp.tool_calls)
            return out
        parsed = parse_verdict_text(resp.text)
        if parsed:
            local = Verdict(
                risk_level=str(parsed.get("risk_level", "low")).lower(),
                verdict=str(parsed.get("verdict", "benign")),
                evidence=str(parsed.get("evidence", "")),
                iocs=parsed.get("iocs", []),
                suggest_action=str(parsed.get("suggest_action", "")),
                model=f"{provider}:{self.gateway.providers[provider].config.model}",
                behavior_hits=unit.behavior_hit_ids,
                truncated=bool(parsed.get("truncated")),
                trace_id=state["trace_id"],
                created_at=timestamp_now(),
                watermark=unit.watermark,
            )
        else:
            local = Verdict(
                verdict="uncertain",
                risk_level="low",
                evidence=f"模型输出无法解析: {resp.text[:200]}",
                model=f"{provider}:{self.gateway.providers[provider].config.model}",
                behavior_hits=unit.behavior_hit_ids,
                trace_id=state["trace_id"],
                created_at=timestamp_now(),
                watermark=unit.watermark,
            )
        out["local"] = local
        return out

    async def tools(self, state: dict) -> dict:
        messages = list(state["messages"])
        last = messages[-1] if messages else {}
        tool_calls = last.get("tool_calls") or []
        results = []
        for tc in tool_calls:
            result = await self.mcp.call(tc["name"], tc.get("arguments") or {})
            results.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "name": tc["name"],
                    "content": json.dumps(result, ensure_ascii=False, default=str),
                }
            )
        messages.extend(results)
        return {"messages": messages}

    async def escalate_check(self, state: dict) -> dict:
        from app.providers.gateway import needs_cloud

        unit: AnalysisUnit = state["unit"]
        local: Verdict | None = state.get("local")
        if local is None:
            return {"provider": self.config.cloud_provider}
        go_cloud = needs_cloud(
            initial_risk=unit.initial_risk,
            local_risk=local.risk_level,
            behavior_hits=len(unit.behavior_hit_ids),
            rule_resolved=unit.rule_resolved,
            requires_chain_analysis=unit.requires_chain_analysis,
            estimated_tool_calls=unit.estimated_tool_calls,
            local_verdict=local.verdict,
            local_parsed=local.verdict != "uncertain",
            anomaly_alert=unit.anomaly_alert,
        )
        return {"provider": self.config.cloud_provider if go_cloud else "edge", "escalated": go_cloud}

    async def verdict_write(self, state: dict) -> dict:
        unit: AnalysisUnit = state["unit"]
        final = state.get("final") or state.get("local")
        if final is None:
            final = Verdict(
                verdict="benign",
                risk_level=unit.initial_risk,
                evidence="规则直接判定/无模型介入",
                behavior_hits=unit.behavior_hit_ids,
                model="rule-engine",
                trace_id=state["trace_id"],
                created_at=timestamp_now(),
                watermark=unit.watermark,
            )
        final.watermark = unit.watermark
        final.trace_id = state["trace_id"]
        # 修复：ack 永远前进 — Redis 写 verdict 在前（即使后续 ES 失败也不阻塞 ack）；
        # ES 写入失败 → outbox 索引暂存 + 后台 retry_outbox 补偿。
        if not self.config.dry_run:
            # 1) 原子写回 Redis（水位 + 结论）— 必成功
            await self.redis.write_verdict(state["session_key"], final.model_dump_json())
            # 2) 实体画像滚动更新（try/except 容错，避免画像失败阻塞后续 ES 写）
            events = state["events"]
            if events:
                ip = events[0].src_ip
                try:
                    await self.redis.append_entity(
                        ip,
                        {
                            "ts": final.created_at,
                            "session": state["session_key"],
                            "verdict": final.verdict,
                            "behavior": unit.behavior_hit_ids,
                        },
                    )
                except Exception:  # noqa: BLE001
                    pass
            # 3) ES 写 verdict — 失败时 outbox 暂存（不阻塞 ack）
            try:
                await self.es.write_verdict(final)
            except Exception as e:  # noqa: BLE001
                outbox_doc = final.model_dump(mode="json")
                outbox_doc["@timestamp"] = final.created_at
                outbox_doc["_target_index"] = self.config.verdict_index
                outbox_doc["_target_doc_type"] = "verdict"
                outbox_doc["trace_id"] = final.trace_id
                outbox_doc["error"] = f"verdict_write failed: {e!s}"[:500]
                await self.es.write_outbox(outbox_doc)
        return {"final": final}

    async def alert(self, state: dict) -> dict:
        final: Verdict = state["final"]
        sess = state["session_key"]
        fp = alert_fingerprint(sess, final.verdict, final.behavior_hits)
        await self.alerts.handle(fp, sess, final, state["trace_id"])
        return {}

    def _default_messages(self, unit: AnalysisUnit) -> list[dict]:
        return [
            {"role": "system", "content": "你是深瞳安全分析智能体。基于聚合摘要与工具结果输出 JSON 结论（risk_level/verdict/evidence/iocs/suggest_action）。"},
            {"role": "user", "content": f"分析任务：\n{json.dumps(unit.model_dump(mode='json'), ensure_ascii=False, default=str)}"},
        ]


def _tc_dict(tc) -> dict:
    return {"id": tc.id, "name": tc.name, "arguments": tc.arguments}


def verdict_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
            "verdict": {"type": "string"},
            "evidence": {"type": "string"},
            "iocs": {"type": "array", "items": {"type": "object"}},
            "suggest_action": {"type": "string"},
            "truncated": {"type": "boolean"},
        },
        "required": ["risk_level", "verdict", "evidence"],
    }
