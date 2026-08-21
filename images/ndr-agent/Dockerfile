# NSS-NDR 本地分析 Agent：
# - LangGraph 状态机（4 步流水线：pre_aggregate → heuristic → llm → reconcile）
# - SqliteCheckpointer 持久化（time travel / 重跑）
# - XDR 升级通道（仅接口，XDR 实际逻辑由 XDR 平台实现）
# - 结构化 Verdict 输出（Pydantic 严格校验）
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir \
    "mcp>=1.0" \
    "fastapi>=0.110" \
    "uvicorn>=0.29" \
    "requests>=2.31" \
    "pyyaml>=6.0" \
    "pydantic>=1.10,<3" \
    "httpx>=0.27" \
    "langgraph>=0.2,<1" \
    "langchain-core>=0.3,<1"

WORKDIR /app
COPY agent.py /app/agent.py

ENV AGENT_HOST=0.0.0.0 AGENT_PORT=8081
EXPOSE 8081

CMD ["python", "/app/agent.py"]