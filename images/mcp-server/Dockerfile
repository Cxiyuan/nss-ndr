# NSS-NDR MCP Server：向本地 Agent 暴露分析工具集（查询本地 ES 元数据）
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=1.0" "elasticsearch>=8.12,<9"

WORKDIR /app
COPY mcp_server.py /app/mcp_server.py

ENV MCP_HOST=0.0.0.0 MCP_PORT=8000
EXPOSE 8000

CMD ["python", "/app/mcp_server.py"]
