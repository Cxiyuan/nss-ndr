#!/usr/bin/env python3
"""NSS-NDR 本地分析 Agent。

职责：接收 XDR 分析任务（经 ndr-manager /api/xdr/agent/task 转发）：
1. LLM 模式（默认）：本地小模型（Ollama，OpenAI 兼容）按工具调用循环推理，
   自主选择并调用 MCP 工具（query_metadata / correlate_session / aggregate_stats /
   get_clue / query_files / list_datasets）完成分析，返回结论 + 工具调用链证据。
2. 结构化降级：未配置模型时，若任务含 target/datasets，直接调用工具并汇总。

安全：
- /analyze 端点要求 Bearer token（与 ndr-manager 配置的 xdr.agent_token 相同）
- 通过 AGENT_MAX_CONCURRENCY 信号量限制并发，避免 Ollama 过载
"""
import asyncio
import json
import os
import secrets
import time
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Request
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# ===== 配置 =====
AGENT_HOST = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8081"))
MCP_URL = os.getenv("MCP_URL", "http://nss-mcp-server:8000/mcp")
LLM_URL = os.getenv("LLM_URL", "http://nss-ollama:11434/v1/chat/completions")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3-ndr")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")  # 远端 OpenAI 兼容端点用
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))
MCP_TIMEOUT = float(os.getenv("MCP_TIMEOUT", "30"))  # MCP 连接超时（秒）
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))
MAX_CONCURRENCY = int(os.getenv("AGENT_MAX_CONCURRENCY", "3"))  # 同时最多 3 个推理任务
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")  # 鉴权 token（与 ndr-manager 的 xdr.agent_token 一致）

app = FastAPI(title="NSS-NDR Agent")

# 并发信号量：限制同时在跑的 LLM 推理任务数
_llm_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

SYSTEM_PROMPT = """你是部署在 NDR 流量探针上的安全分析助手。
你可以使用提供的工具查询探针本地采集的网络元数据（连接、DNS、HTTP、TLS、SMB、文件分析、检测线索等）。
请根据用户的分析任务，自主选择合适的工具分步取证，最后用中文给出分析结论：
- 结论要有依据：引用关键证据（源/目的、域名、端口、特征等）
- 若证据不足，明确说明还需要哪些数据
- 数据全部来自探针本地，不要编造结果
- 工具调用尽量精简，避免重复查询相同数据"""


def _check_auth(request: Request) -> None:
    """校验 Bearer Token（与 ndr-manager 配置的 xdr.agent_token 一致）"""
    if not AGENT_TOKEN:
        # 未配置 AGENT_TOKEN → 拒绝（默认安全）；管理员需显式启用
        raise HTTPException(status_code=503, detail="Agent 未配置 AGENT_TOKEN，请在 docker-compose env 中设置")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer Token")
    token = auth[7:].strip()
    # 常量时间比较，避免时序攻击
    if not secrets.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Agent Token 无效")


# ===== MCP 工具辅助 =====

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


# ===== LLM 调用 =====

def _llm_complete(messages: list[dict], tools: list[dict]) -> dict:
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    payload = {"model": LLM_MODEL, "messages": messages, "tools": tools, "temperature": 0}
    resp = requests.post(LLM_URL, json=payload, timeout=LLM_TIMEOUT, headers=headers)
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
    for step in range(MAX_STEPS):
        try:
            msg = _llm_complete(messages, tools)
        except Exception as e:
            return {"ok": False, "conclusion": f"本地模型调用失败（可配置 LLM_MODEL 或使用结构化任务）: {e}",
                    "llm_used": False, "steps": step, "evidence": evidence}
        if not msg.get("tool_calls"):
            return {"ok": True, "conclusion": msg.get("content") or "(模型未给出结论)",
                    "llm_used": True, "llm_model": LLM_MODEL, "steps": step + 1, "evidence": evidence}
        messages.append(msg)
        for tc in msg["tool_calls"]:
            fn = tc["function"]
            name, args = fn["name"], json.loads(fn.get("arguments") or "{}")
            result = _call_tool(session, name, args)
            evidence.append({"tool": name, "args": args, "result": _truncate(result)})
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
    return {"ok": True, "conclusion": "达到最大推理步数，未得到最终结论", "llm_used": True,
            "llm_model": LLM_MODEL, "steps": MAX_STEPS, "evidence": evidence}


# ===== 结构化降级（覆盖 6 个工具的常见用法）=====

def _run_structured(session: ClientSession, task: dict) -> dict:
    """无 LLM 时：根据任务内容调用最合适的 MCP 工具。

    路由策略：
    - 含 mime/md5 → query_files
    - 含 field/top_n → aggregate_stats
    - 仅 community_id → correlate_session
    - 默认 → query_metadata
    """
    target = task.get("target") or {}
    datasets = task.get("datasets")
    window = task.get("window_seconds", 3600)
    conditions = task.get("conditions")
    fields = task.get("fields")  # 聚合字段

    if not any(target.values()):
        return {"ok": False, "conclusion": "结构化任务缺少 target（community_id/src_ip/dst_ip/uid）",
                "llm_used": False, "evidence": []}

    evidence = []
    used_tools = []

    # 1) 文件查询（如指定 mime_type 或 md5）
    if task.get("mime_type") or task.get("md5"):
        r = _call_tool(session, "query_files",
                       {"mime_type": task.get("mime_type"), "md5": task.get("md5"),
                        "window_seconds": window, "size": 100})
        evidence.append({"tool": "query_files", "args": {k: task.get(k) for k in ["mime_type", "md5"]}, "result": _truncate(r)})
        used_tools.append("query_files")

    # 2) 聚合统计（如指定 fields）
    if fields:
        for f in (fields if isinstance(fields, list) else [fields]):
            r = _call_tool(session, "aggregate_stats",
                           {"target": target, "window_seconds": window, "field": f, "top_n": 10})
            evidence.append({"tool": "aggregate_stats", "args": {"field": f}, "result": _truncate(r)})
            used_tools.append(f"aggregate_stats[{f}]")

    # 3) 关联会话（community_id 给定时）
    cid = target.get("community_id")
    if cid and not datasets:
        r = _call_tool(session, "correlate_session",
                       {"community_id": cid, "window_seconds": window})
        evidence.append({"tool": "correlate_session", "args": {"community_id": cid}, "result": _truncate(r)})
        used_tools.append("correlate_session")
    else:
        # 4) 通用元数据查询
        r = _call_tool(session, "query_metadata",
                       {"target": target, "datasets": datasets, "window_seconds": window, "conditions": conditions})
        evidence.append({"tool": "query_metadata", "args": {"target": target, "datasets": datasets}, "result": _truncate(r)})
        used_tools.append("query_metadata")

    if not used_tools:
        return {"ok": False, "conclusion": "无法路由到任何工具，请检查 target/datasets/fields", "llm_used": False, "evidence": []}

    return {"ok": True,
            "conclusion": f"已按目标 {target} 检索关联元数据（{', '.join(used_tools)}），详见 evidence",
            "llm_used": False, "evidence": evidence}


def _truncate(s: str, n: int = 4000) -> str:
    return s if len(s) <= n else s[:n] + f"...(截断，共 {len(s)} 字符)"


# ===== 端点 =====

@app.post("/analyze")
async def analyze(req: Request):
    # 鉴权
    _check_auth(req)

    task = await req.json()
    task_id = task.get("task_id") or "unknown"
    instruction = task.get("instruction") or ""
    target = task.get("target")
    started = time.monotonic()

    async with _llm_semaphore:
        try:
            async with streamablehttp_client(MCP_URL, timeout=MCP_TIMEOUT) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    if LLM_MODEL:
                        result = _run_llm_agent(session, instruction, target)
                    else:
                        result = _run_structured(session, task)
        except Exception as e:
            result = {"ok": False, "conclusion": f"MCP 连接失败: {e}", "llm_used": False, "evidence": []}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    result["task_id"] = task_id
    result["elapsed_ms"] = elapsed_ms
    return result


@app.get("/healthz")
async def healthz():
    """健康检查（无需鉴权）"""
    return {"status": "ok", "llm_model": LLM_MODEL or "(structured-only)", "max_concurrency": MAX_CONCURRENCY}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT)