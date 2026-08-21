#!/usr/bin/env python3
"""NSS-NDR 本地分析 Agent：LangGraph 状态机 + XDR 升级通道。

定位：NDR 后端威胁分析引擎（无用户交互界面）。

状态机（LangGraph StateGraph）：
    [pre_aggregate] → [heuristic] ─┬─ high conf → [finalize]
                                  └─ low conf  → [llm_classify] ─┬─ 不升级 → [finalize]
                                                              └─ 升级   → [escalate_xdr] → [finalize]

节点全部 async；SqliteCheckpointer 自动持久化（time travel / 重跑）。
XDR 升级通道：仅接口，XDR 不可达/超时 → 返回 None 降级。
"""
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Literal, Optional, TypedDict

import httpx
import requests
import secrets
from fastapi import FastAPI, HTTPException, Request
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Pydantic 严格 Verdict schema
from pydantic import BaseModel, Field, ValidationError, validator

# LangGraph
from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.sqlite import SqliteCheckpointer

# ===== 配置 =====
AGENT_HOST = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8081"))
MCP_URL = os.getenv("MCP_URL", "http://nss-mcp-server:8000/mcp")
LLM_URL = os.getenv("LLM_URL", "http://nss-ollama:11434/v1/chat/completions")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3-ndr")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))
MCP_TIMEOUT = float(os.getenv("MCP_TIMEOUT", "30"))
MAX_CONCURRENCY = int(os.getenv("AGENT_MAX_CONCURRENCY", "3"))
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")

# ndr-manager 回调（最终状态同步到 ndr-manager 的展示表）
NDR_MANAGER_URL = os.getenv("NDR_MANAGER_URL", "http://ndr-manager:8080")

# XDR 升级通道
XDR_BASE_URL = os.getenv("XDR_BASE_URL", "")
XDR_TOKEN = os.getenv("XDR_TOKEN", "")
XDR_TIMEOUT = int(os.getenv("XDR_TIMEOUT", "60"))
XDR_INSECURE_TLS = os.getenv("XDR_INSECURE_TLS", "false").lower() == "true"

# LangGraph 状态持久化
LANGGRAPH_DB_PATH = os.getenv("LANGGRAPH_DB_PATH", "/opt/agent/state/langgraph.db")

# 阈值
HIGH_HEURISTIC_THRESHOLD = 0.85
MEDIUM_LLM_THRESHOLD = 0.7
LLM_SAMPLE_TEMPS = [0.0, 0.3, 0.7]
LLM_PARSE_RETRIES = 3

# 升级判定 - 显式复杂任务
COMPLEX_INSTRUCTIONS = {"incident_cause", "blast_radius", "ioc_confirm", "deep_dive"}

app = FastAPI(title="NSS-NDR Agent")
_llm_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)


# ===== 严格 Verdict Schema（Pydantic）=====

class Verdict(BaseModel):
    verdict: Literal["real_threat", "suspicious", "noise", "insufficient_evidence"]
    confidence: float = Field(..., ge=0.0, lt=1.0)
    severity: Literal["critical", "high", "medium", "low", "info"]
    summary: str = Field(..., min_length=1, max_length=500)
    recommended_action: Literal["isolate_host", "block_ip", "monitor", "no_action"]
    key_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    escalation_reason: Optional[str] = None

    @validator("confidence")
    def _cap_confidence(cls, v):
        if v >= 1.0:
            raise ValueError("confidence must be < 1.0 (small model limitation)")
        return v

    @validator("key_indicators")
    def _limit_indicators(cls, v):
        return v[:10]


# ===== LangGraph 状态 =====
# 节点返回 partial dict（update state），LangGraph 自动 merge
class AnalysisState(TypedDict, total=False):
    # 任务输入
    task_id: str
    instruction: str
    target: Dict[str, Any]
    # 跨任务记忆（reputation_check 节点产出）
    reputation: Optional[Dict[str, Any]]      # {cached, ip, last_verdict, last_confidence, ...}
    # STEP 1 输出
    metrics: Optional[Dict[str, Any]]
    # STEP 2 输出
    heuristic: Optional[Dict[str, Any]]
    # STEP 3 输出
    llm_verdict: Optional[Dict[str, Any]]     # dict（Pydantic Verdict.dict()）
    # STEP 4 输出
    xdr_verdict: Optional[Dict[str, Any]]
    # 最终
    final: Optional[Dict[str, Any]]           # dict（Pydantic Verdict.dict()）
    # 元
    llm_used: bool
    escalated: bool
    elapsed_ms: int
    cached: bool                             # 是否走了 short_circuit（信誉命中）


# ===== 鉴权 =====
def _check_auth(request: Request) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="Agent 未配置 AGENT_TOKEN")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer Token")
    token = auth[7:].strip()
    if not secrets.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Agent Token 无效")


# ===== System Prompt（小模型约束模板）=====
SYSTEM_PROMPT = """你是 NDR 后端威胁分析引擎。任务：基于结构化指标输出 JSON 判定。

【硬约束】
1. 仅基于输入的 metrics，禁止编造数字
2. 输出必须符合 Verdict schema（严格 JSON）
3. confidence < 1.0（小模型限制）
4. ambiguous 时 verdict = "insufficient_evidence" + escalation_reason
5. 失败时输出 {"error": "..."}，不要猜测

【Verdict schema】
{
  "verdict": "real_threat | suspicious | noise | insufficient_evidence",
  "confidence": 0.0-0.99,
  "severity": "critical | high | medium | low | info",
  "summary": "1-2 句中文结论",
  "recommended_action": "isolate_host | block_ip | monitor | no_action",
  "key_indicators": [{"type": "...", "value": "..."}],
  "escalation_reason": null 或 "string"
}

【示例 1 — IOC 命中】
输入: {"heuristic": {"confidence": 0.95, "reason": "IOC matched"}, "metrics": {"ioc_match": {"matched": true, "hit_count": 1}, "suricata_top_rules": [{"key": "ET MALWARE Cobalt Strike", "count": 5}]}}
输出: {"verdict": "real_threat", "confidence": 0.95, "severity": "high", "summary": "命中已知 C2 IOC，且 Suricata 检测到 Cobalt Strike Beacon 行为", "recommended_action": "isolate_host", "key_indicators": [{"type": "ioc_match", "value": "8.8.8.8"}, {"type": "rule_match", "value": "ET MALWARE Cobalt Strike", "count": 5}], "escalation_reason": null}

【示例 2 — 无告警】
输入: {"heuristic": {"confidence": 0.9, "reason": "no alerts"}, "metrics": {"ioc_match": {"matched": false}, "suricata_top_rules": []}}
输出: {"verdict": "noise", "confidence": 0.95, "severity": "info", "summary": "无 Suricata 告警、无 IOC 命中，纯噪声", "recommended_action": "no_action", "key_indicators": [], "escalation_reason": null}

【示例 3 — 模糊】
输入: {"heuristic": {"confidence": 0.4, "reason": "ambiguous"}, "metrics": {"ioc_match": {"matched": false}, "suricata_top_rules": [{"key": "ET ATTACK Reconnaissance", "count": 2}]}}
输出: {"verdict": "suspicious", "confidence": 0.6, "severity": "medium", "summary": "低频 Reconnaissance 触发，无明确 IOC，模式模糊", "recommended_action": "monitor", "key_indicators": [{"type": "rule_match", "value": "ET ATTACK Reconnaissance", "count": 2}], "escalation_reason": "low_freq_alerts_ambiguous_threat"}
"""


# ===== LangGraph 节点 =====

async def _call_tool_safe(session: ClientSession, name: str, args: dict) -> dict:
    try:
        result = await asyncio.to_thread(session.call_tool, name, arguments=args)
        texts = []
        for c in result.content:
            txt = getattr(c, "text", None)
            if txt:
                texts.append(txt)
        if not texts:
            return {"error": "empty result"}
        try:
            return json.loads(texts[0])
        except json.JSONDecodeError:
            return {"raw": texts[0]}
    except Exception as e:
        return {"error": f"tool {name} failed: {e}"}


# ---- 节点 1: pre_aggregate ----
async def pre_aggregate_node(state: AnalysisState) -> dict:
    target = state["target"]
    async with streamablehttp_client(MCP_URL, timeout=MCP_TIMEOUT) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            results = await asyncio.gather(
                _call_tool_safe(session, "aggregate_suricata", {"target": target, "field": "rule.name", "top_n": 5}),
                _call_tool_safe(session, "aggregate_suricata", {"target": target, "field": "source.ip", "top_n": 5}),
                _call_tool_safe(session, "aggregate_stats", {"target": target, "field": "destination.port", "top_n": 5}),
                _call_tool_safe(session, "aggregate_stats", {"target": target, "field": "dns.question.name", "top_n": 5}),
                _call_tool_safe(session, "check_ioc", {"target": target}),
                _call_tool_safe(session, "get_indicators", {"target": target, "max_events": 30}),
            )
    (suricata_rules, suricata_ips, conn_ports, dns_names, ioc_match, indicators) = results

    return {
        "metrics": {
            "suricata_top_rules": suricata_rules.get("top", []),
            "suricata_top_ips": suricata_ips.get("top", []),
            "conn_top_ports": conn_ports.get("top", []),
            "dns_top_names": dns_names.get("top", []),
            "ioc_match": ioc_match,
            "indicators_summary": {
                "total_events": indicators.get("total_events", 0),
                "per_source_counts": indicators.get("per_source_counts", {}),
            },
        }
    }


# ---- 节点 2: heuristic ----
def apply_heuristics(metrics: dict) -> dict:
    if metrics.get("ioc_match", {}).get("matched"):
        return {"confidence": 0.95, "reason": "IOC matched", "verdict_hint": "real_threat", "severity_hint": "high"}
    top_rules = metrics.get("suricata_top_rules", [])
    top_ips = metrics.get("suricata_top_ips", [])
    if not top_rules or top_rules[0].get("count", 0) == 0:
        return {"confidence": 0.9, "reason": "no alerts", "verdict_hint": "noise", "severity_hint": "info"}
    if top_rules[0].get("count", 0) >= 10:
        return {"confidence": 0.85, "reason": f"rule {top_rules[0].get('key', '?')} fired ≥10 times", "verdict_hint": "real_threat", "severity_hint": "high"}
    if top_ips and len(top_ips) >= 3 and top_rules[0].get("count", 0) >= 5:
        return {"confidence": 0.8, "reason": "multiple sources triggering same rule (campaign)", "verdict_hint": "real_threat", "severity_hint": "medium"}
    return {"confidence": 0.4, "reason": "ambiguous metrics", "verdict_hint": None, "severity_hint": None}


def heuristic_to_verdict(heuristic: dict, _metrics: dict) -> Verdict:
    if heuristic["verdict_hint"] == "real_threat":
        return Verdict(verdict="real_threat", confidence=heuristic["confidence"],
                       severity=heuristic["severity_hint"] or "high",
                       summary=f"启发式判定: {heuristic['reason']}",
                       recommended_action="monitor",
                       key_indicators=[{"type": "heuristic_rule", "value": heuristic["reason"]}])
    if heuristic["verdict_hint"] == "noise":
        return Verdict(verdict="noise", confidence=heuristic["confidence"],
                       severity="info", summary=f"启发式判定: {heuristic['reason']}",
                       recommended_action="no_action", key_indicators=[])
    return Verdict(verdict="insufficient_evidence", confidence=heuristic["confidence"],
                   severity="info", summary=f"启发式无法判定: {heuristic['reason']}",
                   recommended_action="no_action", key_indicators=[])


async def heuristic_node(state: AnalysisState) -> dict:
    h = apply_heuristics(state["metrics"])
    return {"heuristic": h}


def route_after_heuristic(state: AnalysisState) -> str:
    """高置信度直接 final；模糊走 LLM"""
    if state["heuristic"]["confidence"] >= HIGH_HEURISTIC_THRESHOLD:
        return "finalize"
    return "llm"


# ---- 节点 3: llm_classify ----
def _llm_call_sync(instruction: str, metrics: dict, heuristic: dict, temperature: float) -> dict:
    user_payload = {"instruction": instruction, "heuristic": heuristic, "metrics": metrics}
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": temperature,
    }
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    resp = requests.post(LLM_URL, json=payload, timeout=LLM_TIMEOUT, headers=headers)
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return json.loads(content)


async def llm_classify_single(instruction: str, metrics: dict, heuristic: dict, temperature: float) -> Optional[Verdict]:
    for attempt in range(LLM_PARSE_RETRIES):
        try:
            raw = await asyncio.to_thread(_llm_call_sync, instruction, metrics, heuristic, temperature)
            return Verdict.parse_obj(raw)
        except (ValidationError, json.JSONDecodeError, Exception):
            if attempt < LLM_PARSE_RETRIES - 1:
                continue
            return None
    return None


async def llm_classify_multi(instruction: str, metrics: dict, heuristic: dict) -> Verdict:
    samples: List[Verdict] = []
    for temp in LLM_SAMPLE_TEMPS:
        verdict = await llm_classify_single(instruction, metrics, heuristic, temp)
        if verdict is not None:
            samples.append(verdict)

    if not samples:
        return heuristic_to_verdict(heuristic, metrics)

    verdict_counts: Dict[str, int] = {}
    for v in samples:
        verdict_counts[v.verdict] = verdict_counts.get(v.verdict, 0) + 1
    majority = max(verdict_counts, key=verdict_counts.get)

    if verdict_counts[majority] >= 2:
        for v in samples:
            if v.verdict == majority:
                return v

    return Verdict(verdict="insufficient_evidence", confidence=0.4, severity="info",
                   summary=f"本地小模型 {len(samples)} 次采样不一致（{verdict_counts}），需人工复核",
                   recommended_action="monitor",
                   key_indicators=[{"type": "llm_inconsistency", "value": str(verdict_counts)}],
                   escalation_reason="llm_samples_inconsistent")


async def llm_node(state: AnalysisState) -> dict:
    if not LLM_MODEL:
        return {"llm_verdict": heuristic_to_verdict(state["heuristic"], state["metrics"]).dict(),
                "llm_used": False}
    verdict = await llm_classify_multi(state["instruction"], state["metrics"], state["heuristic"])
    return {"llm_verdict": verdict.dict(), "llm_used": True}


def should_escalate(llm_verdict: dict, heuristic: dict, instruction: str) -> bool:
    if not XDR_BASE_URL:
        return False
    if instruction in COMPLEX_INSTRUCTIONS:
        return True
    if llm_verdict.get("escalation_reason"):
        return True
    if heuristic["confidence"] >= 0.7 and llm_verdict.get("confidence", 0) < 0.7:
        return True
    if llm_verdict.get("confidence", 0) < 0.5 and llm_verdict.get("verdict") == "insufficient_evidence":
        return True
    return False


def route_after_llm(state: AnalysisState) -> str:
    if state.get("llm_verdict") and should_escalate(state["llm_verdict"], state["heuristic"], state["instruction"]):
        return "escalate"
    return "finalize"


# ---- 节点 4: escalate_xdr ----
async def escalate_to_xdr(task_id: str, instruction: str, target: dict, context: dict) -> Optional[dict]:
    if not XDR_BASE_URL or not XDR_TOKEN:
        return None
    try:
        async with httpx.AsyncClient(timeout=XDR_TIMEOUT, verify=not XDR_INSECURE_TLS) as client:
            payload = {
                "task_id": f"ndr-esc-{task_id}",
                "tier": 2,
                "instruction": instruction,
                "target": target,
                "ndr_context": context,
                "schema_version": "1.0",
            }
            headers = {"Authorization": f"Bearer {XDR_TOKEN}", "Content-Type": "application/json"}
            url = f"{XDR_BASE_URL.rstrip('/')}/api/xdr/analyze_v2"
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            verdict_data = data.get("verdict") or data
            return verdict_data if isinstance(verdict_data, dict) else None
    except Exception as e:
        print(f"[agent] XDR 升级失败: {e}", file=sys.stderr)
        return None


async def escalate_node(state: AnalysisState) -> dict:
    xdr = await escalate_to_xdr(
        state["task_id"], state["instruction"], state["target"],
        context={
            "metrics": state["metrics"],
            "heuristic": state["heuristic"],
            "ndr_llm_verdict": state["llm_verdict"],
        },
    )
    return {"xdr_verdict": xdr, "escalated": xdr is not None}


# ---- 节点 5: finalize ----
def reconcile(heuristic: dict, llm_verdict: Optional[dict], xdr_verdict: Optional[dict]) -> dict:
    if xdr_verdict is not None:
        return xdr_verdict
    if llm_verdict is not None:
        return llm_verdict
    return heuristic_to_verdict(heuristic, {}).dict()


async def finalize_node(state: AnalysisState) -> dict:
    final = reconcile(state["heuristic"], state.get("llm_verdict"), state.get("xdr_verdict"))
    return {"final": final}


# ===== 跨任务记忆：IP 信誉节点 =====

async def reputation_check_node(state: AnalysisState) -> dict:
    """跨任务记忆：先查 IP 信誉缓存（ndr-manager 维护）"""
    target = state.get("target") or {}
    src_ip = target.get("src_ip", "")
    if not src_ip:
        return {"reputation": {"cached": False}}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            headers = {"Authorization": f"Bearer {AGENT_TOKEN}"}
            url = f"{NDR_MANAGER_URL.rstrip('/')}/api/agent/ip_reputation/{src_ip}"
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                return {"reputation": {"cached": False}}
            data = response.json()
            if not data.get("analyzed"):
                return {"reputation": {"cached": False}}
            return {
                "reputation": {
                    "cached": True,
                    "ip": data.get("ip"),
                    "last_verdict": data.get("last_verdict"),
                    "last_confidence": data.get("last_confidence"),
                    "last_analyzed_at": data.get("last_analyzed_at"),
                    "analysis_count": data.get("analysis_count", 1),
                    "expires_at": data.get("expires_at"),
                }
            }
    except Exception as e:
        print(f"[agent] 信誉查询失败: {e}", file=sys.stderr)
        return {"reputation": {"cached": False}}


def should_short_circuit(state: AnalysisState) -> bool:
    """是否用缓存 verdict 短路？需满足：高置信 + 高置信 verdict + 未过期"""
    rep = state.get("reputation") or {}
    if not rep.get("cached"):
        return False
    expires_at = rep.get("expires_at", "")
    if expires_at:
        try:
            from datetime import datetime as _dt
            exp = _dt.fromisoformat(expires_at.replace("Z", "+00:00"))
            if _dt.now(exp.tzinfo) > exp:
                return False  # 已过期
        except Exception:
            return False
    if rep.get("last_verdict") not in {"real_threat", "noise"}:
        return False
    if rep.get("last_confidence", 0) < 0.7:
        return False
    return True


def route_after_reputation(state: AnalysisState) -> str:
    """信誉命中 → 短路；否则走完整流水线"""
    if should_short_circuit(state):
        return "short_circuit"
    return "pre_aggregate"


async def short_circuit_node(state: AnalysisState) -> dict:
    """信誉命中：直接用缓存 verdict，跳过 heuristic/llm/escalate"""
    rep = state["reputation"]
    verdict = rep["last_verdict"]
    is_threat = verdict == "real_threat"
    return {
        "final": {
            "verdict": verdict,
            "confidence": rep["last_confidence"],
            "severity": "high" if is_threat else "info",
            "summary": f"信誉命中：IP {rep['ip']} 过去 {rep['analysis_count']} 次分析为 {verdict}（最近于 {rep['last_analyzed_at']}）",
            "recommended_action": "isolate_host" if is_threat else "no_action",
            "key_indicators": [{
                "type": "reputation_cache",
                "value": f"IP {rep['ip']} 过去 {rep['analysis_count']} 次分析为 {verdict}",
            }],
            "escalation_reason": None,
        },
        "llm_used": False,
        "escalated": False,
        "cached": True,
    }


async def reputation_write_node(state: AnalysisState) -> dict:
    """跨任务记忆：完整分析后写入 IP 信誉缓存（短路路径也写以更新 timestamp/count）"""
    target = state.get("target") or {}
    src_ip = target.get("src_ip", "")
    if not src_ip:
        return {}
    final = state.get("final") or {}
    verdict = final.get("verdict", "")
    confidence = final.get("confidence", 0.0)
    # 仅缓存明确判定（real_threat / noise）
    if verdict not in {"real_threat", "noise"}:
        return {}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"}
            url = f"{NDR_MANAGER_URL.rstrip('/')}/api/agent/ip_reputation/{src_ip}"
            payload = {"last_verdict": verdict, "last_confidence": confidence}
            response = await client.put(url, json=payload, headers=headers)
            if response.status_code >= 400:
                print(f"[agent] 信誉写入失败: {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"[agent] 信誉写入异常: {e}", file=sys.stderr)
    return {}


# ===== 构建 LangGraph 状态机 =====
def build_graph():
    builder = StateGraph(AnalysisState)
    builder.add_node("reputation_check", reputation_check_node)
    builder.add_node("short_circuit", short_circuit_node)
    builder.add_node("pre_aggregate", pre_aggregate_node)
    builder.add_node("heuristic", heuristic_node)
    builder.add_node("llm", llm_node)
    builder.add_node("escalate", escalate_node)
    builder.add_node("finalize", finalize_node)
    builder.add_node("reputation_write", reputation_write_node)

    # 入口：先查跨任务记忆
    builder.add_edge(START, "reputation_check")
    # 信誉命中 → 短路；未命中 → 完整 4 步
    builder.add_conditional_edges(
        "reputation_check", route_after_reputation,
        {"short_circuit": "short_circuit", "pre_aggregate": "pre_aggregate"},
    )
    # 短路路径：直接 final → 写信誉缓存
    builder.add_edge("short_circuit", "reputation_write")
    # 完整路径：pre_aggregate → heuristic → (llm | finalize) → (escalate | finalize) → finalize → 写信誉
    builder.add_edge("pre_aggregate", "heuristic")
    builder.add_conditional_edges(
        "heuristic", route_after_heuristic,
        {"llm": "llm", "finalize": "finalize"},
    )
    builder.add_conditional_edges(
        "llm", route_after_llm,
        {"escalate": "escalate", "finalize": "finalize"},
    )
    builder.add_edge("escalate", "finalize")
    builder.add_edge("finalize", "reputation_write")
    builder.add_edge("reputation_write", END)
    return builder


# 持久化：SqliteCheckpointer（time travel）+ 失败降级到 MemorySaver（仅内存）
def _build_checkpointer():
    os.makedirs(os.path.dirname(LANGGRAPH_DB_PATH), exist_ok=True)
    # URL 格式：sqlite:////absolute/path（4 个 / 表示绝对路径）
    db_url = f"sqlite:///{LANGGRAPH_DB_PATH}"
    try:
        return SqliteCheckpointer.from_conn_string(db_url)
    except Exception as e:
        print(f"[agent] SqliteCheckpointer 初始化失败（{e}），降级到 MemorySaver（time travel 仅进程内）", file=sys.stderr)
        from langgraph.checkpoint.memory import MemorySaver
        return MemorySaver()


_checkpointer = _build_checkpointer()
_graph = build_graph().compile(checkpointer=_checkpointer)


# ===== 状态同步到 ndr-manager（仅最终状态展示） =====
async def save_state_to_ndr_manager(task_id: str, state: dict) -> None:
    """最终状态同步给 ndr-manager（用于 UI 展示与审计）"""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"}
            url = f"{NDR_MANAGER_URL.rstrip('/')}/api/agent/analysis_state/{task_id}"
            response = await client.put(url, json=state, headers=headers)
            if response.status_code >= 400:
                print(f"[agent] 保存状态失败 {response.status_code}: {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"[agent] 保存状态异常: {e}", file=sys.stderr)


# ===== FastAPI 端点 =====
@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "model": LLM_MODEL or "(structured-only)",
        "xdr_escalation_enabled": bool(XDR_BASE_URL),
        "langgraph_db": LANGGRAPH_DB_PATH,
        "max_concurrency": MAX_CONCURRENCY,
    }


@app.post("/analyze")
async def analyze(req: Request):
    """主端点：执行 4 步 LangGraph 状态机"""
    _check_auth(req)
    task = await req.json()
    task_id = task.get("task_id") or "unknown"
    instruction = task.get("instruction") or "is_threat"
    target = task.get("target") or {}

    config = {"configurable": {"thread_id": task_id}}
    started = time.monotonic()

    async with _llm_semaphore:
        try:
            result = await _graph.ainvoke({
                "task_id": task_id,
                "instruction": instruction,
                "target": target,
                "llm_used": False,
                "escalated": False,
                "elapsed_ms": 0,
            }, config=config)
        except Exception as e:
            result = {
                "task_id": task_id, "instruction": instruction, "target": target,
                "metrics": None, "heuristic": {"confidence": 0.0, "reason": "pipeline_failed"},
                "llm_verdict": None, "xdr_verdict": None,
                "final": Verdict(verdict="insufficient_evidence", confidence=0.0,
                                severity="info", summary=f"本地推理失败: {e}",
                                recommended_action="no_action").dict(),
                "llm_used": False, "escalated": False, "elapsed_ms": 0,
            }

    elapsed_ms = int((time.monotonic() - started) * 1000)
    final = result["final"]

    # 同步最终状态到 ndr-manager（供 UI 展示；完整状态在 LangGraph SqliteCheckpointer）
    await save_state_to_ndr_manager(task_id, {
        "task_id": task_id,
        "instruction": instruction,
        "target": target,
        "stage": "finalized",
        "metrics": result.get("metrics"),
        "heuristic_verdict": result.get("heuristic"),
        "llm_verdict": result.get("llm_verdict"),
        "xdr_verdict": result.get("xdr_verdict"),
        "final_verdict": final,
        "llm_used": result.get("llm_used", False),
        "escalated": result.get("escalated", False),
        "elapsed_ms": elapsed_ms,
    })

    return {
        "task_id": task_id,
        "verdict": final["verdict"],
        "confidence": final["confidence"],
        "severity": final["severity"],
        "summary": final["summary"],
        "recommended_action": final["recommended_action"],
        "key_indicators": final.get("key_indicators", []),
        "escalation_reason": final.get("escalation_reason"),
        "model": LLM_MODEL if result.get("llm_used") else None,
        "llm_used": result.get("llm_used", False),
        "escalated": result.get("escalated", False),
        "cached": result.get("cached", False),  # M14: short_circuit 命中
        "elapsed_ms": elapsed_ms,
    }


@app.get("/state/{task_id}")
async def get_state(task_id: str):
    """时间旅行：返回 task 完整推理路径（LangGraph state checkpoint）"""
    config = {"configurable": {"thread_id": task_id}}
    state = await _graph.aget_state(config)
    if not state or not state.values:
        raise HTTPException(status_code=404, detail="task 不存在")
    return {
        "task_id": task_id,
        "values": state.values,
        "next_steps": state.next,  # 下一个要执行的节点
    }


@app.post("/state/{task_id}/replay")
async def replay_state(task_id: str, req: Request):
    """时间旅行：从指定 checkpoint 重跑（可选改写 state 后重跑）"""
    _check_auth(req)
    body = await req.json() if (await req.body()) else {}
    config = {"configurable": {"thread_id": task_id}}
    # 可选：改写 state（用于 A/B test 不同 prompt）
    if "values" in body:
        await _graph.aupdate_state(config, body["values"])
    # 重跑
    result = await _graph.ainvoke(None, config=config)
    return {"task_id": task_id, "values": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT)