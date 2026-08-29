"""LangGraph 图编排（设计文档 §9）：缓存 → 聚合 → 模型/工具 → 升级 → 写回 → 告警。"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.pipeline.nodes import Nodes
from app.pipeline.state import AgentState


def build_graph(nodes: Nodes, checkpointer: Any | None = None) -> CompiledStateGraph:
    g = StateGraph(AgentState)

    g.add_node("cache_lookup", nodes.cache_lookup)
    g.add_node("aggregate", nodes.aggregate)
    g.add_node("model", nodes.model)
    g.add_node("tools", nodes.tools)
    g.add_node("escalate_check", nodes.escalate_check)
    g.add_node("verdict_write", nodes.verdict_write)
    g.add_node("alert", nodes.alert)

    g.add_edge(START, "cache_lookup")
    g.add_conditional_edges(
        "cache_lookup",
        lambda s: END if s.get("reused") else "aggregate",
        {"aggregate": "aggregate", END: END},
    )
    g.add_conditional_edges(
        "aggregate",
        lambda s: "verdict_write" if s["unit"].rule_resolved and s["unit"].behavior_hits else "model",
        {"verdict_write": "verdict_write", "model": "model"},
    )
    g.add_conditional_edges(
        "model",
        lambda s: "tools"
        if (s.get("messages") and s["messages"][-1].get("tool_calls") and s.get("tool_calls_made", 0) < nodes.config.max_tool_calls)
        else ("escalate_check" if s.get("provider") == nodes.config.default_provider else "verdict_write"),
        {"tools": "tools", "escalate_check": "escalate_check", "verdict_write": "verdict_write"},
    )
    g.add_edge("tools", "model")
    g.add_conditional_edges(
        "escalate_check",
        lambda s: "model" if s.get("escalated") else "verdict_write",
        {"model": "model", "verdict_write": "verdict_write"},
    )
    g.add_edge("verdict_write", "alert")
    g.add_edge("alert", END)

    return g.compile(checkpointer=checkpointer)
