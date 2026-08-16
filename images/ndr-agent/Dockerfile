# NSS-NDR 本地分析 Agent：接收 XDR 分析任务，通过 MCP 调用探针工具集完成分析
# LLM 推理走 Ollama（OpenAI 兼容）；未配置模型时降级为结构化任务直调工具
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=1.0" "fastapi>=0.110" "uvicorn>=0.29" "requests>=2.31" "pyyaml>=6.0"

WORKDIR /app
COPY agent.py /app/agent.py

ENV AGENT_HOST=0.0.0.0 AGENT_PORT=8081
EXPOSE 8081

CMD ["python", "/app/agent.py"]
