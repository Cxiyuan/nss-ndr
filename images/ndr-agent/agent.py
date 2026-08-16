#!/usr/bin/env python3
"""NSS-NDR 本地分析 Agent。

职责：接收 XDR 分析任务（经 ndr-manager /api/xdr/agent/task 转发）：
1. LLM 模式（默认）：本地小模型（Ollama，OpenAI 兼容）按工具调用循环推理，
   自主选择并调用 MCP 工具（query_metadata / correlate_session / aggregate_stats /
   get_clue / query_files / list_datasets）完成分析，返回结论 + 工具调用链证据。
2. 结构化降级：未配置模型时，若任务含 target/datasets，直接调用工具并汇总。
"""
import json
import os
import sys
from typing import Any

import requests
import yaml
from fastapi import FastAPI, Request
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

AGENT_HOST = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8081"))
MCP_URL = os.getenv("MCP_URL", "http://nss-mcp-server:8000/mcp")
LLM_URL = os.getenv("LLM_URL", "http://nss-ollama:11434/v1/chat/completions")
LLM_MODEL = os.getenv("LLM_MODEL", "")          # 如 qwen2.5:3b；留空则结构化降级
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))

app = FastAPI(title="NSS-NDR Agent")

SYSTEM_PROMPT = """你是部署在 NDR 流量探针上的安全分析助手。
你可以使用提供的工具查询探针本地采集的网络元数据（连接、DNS、HTTP、TLS、SMB、文件分析、检测线索等）。
请根据用户的分析任务，自主选择合适的工具分步取证，最后用中文给出分析结论：
- 结论要有依据：引用关键证据（源/目的、域名、端口、特征等）
- 若证据不足，明确说明还需要哪些数据
- 数据全部来自探针本地，不要编造结果。"""


def _load_tools(session: ClientSession) -> list[dict]:
    tools = []
    resp = session.list_tools()
    for t in resp.tools:
        tools.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        })
    return tools


def _call_tool(session: ClientSession, name: str, args: dict) -> Any:
    try:
        result = session.call_tool(name, arguments=args)
        # MCP 返回 ContentBlock 列表
        texts = []
        for c in result.content:
            txt = getattr(c, "text", None)
            if txt:
                texts.append(txt)
        if not texts:
            texts.append(str(result))
        return "\n".join(texts)
    except Exception as e:
        return f"工具调用失败: {e}"


def _llm_complete(messages: list[dict], tools: list[dict]) -> dict:
    payload = {"model": LLM_MODEL, "messages": messages, "tools": tools, "temperature": 0}
    resp = requests.post(LLM_URL, json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]


def _run_llm_agent(session: ClientSession, instruction: str, target: dict | None) -> dict:
    tools = _load_tools(session)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    user_content = f"分析任务：{instruction}"
    if target:
        user_content += f"\n目标：{json.dumps(target, ensure_ascii=False)}"
    messages.append({"role": "user", "content": user_content})

    evidence = []
    for _ in range(MAX_STEPS):
        try:
            msg = _llm_complete(messages, tools)
        except Exception as e:
            return {"ok": False, "conclusion": f"本地模型调用失败（可配置 LLM_MODEL 或使用结构化任务）: {e}",
                    "llm_used": False, "evidence": evidence}
        if not msg.get("tool_calls"):
            return {"ok": True, "conclusion": msg.get("content") or "(模型未给出结论)",
                    "llm_used": True, "llm_model": LLM_MODEL, "evidence": evidence}
        messages.append(msg)
        for tc in msg["tool_calls"]:
            fn = tc["function"]
            name, args = fn["name"], json.loads(fn.get("arguments") or "{}")
            result = _call_tool(session, name, args)
            evidence.append({"tool": name, "args": args, "result": _truncate(result)})
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
    return {"ok": True, "conclusion": "达到最大推理步数，未得到最终结论", "llm_used": True,
            "llm_model": LLM_MODEL, "evidence": evidence}


def _run_structured(session: ClientSession, task: dict) -> dict:
    """无 LLM 时：结构化任务直接调用工具并汇总。"""
    target = task.get("target") or {}
    datasets = task.get("datasets")
    window = task.get("window_seconds", 3600)
    if not any(target.values()):
        return {"ok": False, "conclusion": "结构化任务缺少 target（community_id/src_ip/dst_ip/uid）",
                "llm_used": False, "evidence": []}
    if datasets:
        result = _call_tool(session, "query_metadata",
                            {"target": target, "datasets": datasets, "window_seconds": window})
    else:
        cid = target.get("community_id")
        if cid:
            result = _call_tool(session, "correlate_session",
                                {"community_id": cid, "window_seconds": window})
        else:
            result = _call_tool(session, "query_metadata",
                                {"target": target, "window_seconds": window})
    return {"ok": True, "conclusion": f"已按目标 {target} 检索关联元数据，共命中见 evidence",
            "llm_used": False, "evidence": [{"tool": "metadata_query", "args": task, "result": _truncate(result)}]}


def _truncate(s: str, n: int = 4000) -> str:
    return s if len(s) <= n else s[:n] + f"...(截断，共 {len(s)} 字符)"


@app.post("/analyze")
async def analyze(req: Request):
    task = await req.json()
    task_id = task.get("task_id") or "unknown"
    instruction = task.get("instruction") or ""
    target = task.get("target")
    # MCP 会话（streamable HTTP）
    try:
        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                if LLM_MODEL:
                    result = _run_llm_agent(session, instruction, target)
                else:
                    result = _run_structured(session, task)
    except Exception as e:
        result = {"ok": False, "conclusion": f"MCP 连接失败: {e}", "llm_used": False, "evidence": []}
    result["task_id"] = task_id
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT)
