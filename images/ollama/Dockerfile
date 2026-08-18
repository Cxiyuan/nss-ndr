# NSS-NDR Ollama 镜像（纯 CPU 优化版）
# 不烘入模型权重——GGUF 通过 docker-compose volume 外挂到 /models/
# （避免大文件入镜像，CI 构建无需上传 GGUF）
#
# 构建：
#   docker build -t nss-ndr-ollama -f images/ollama/Dockerfile images/ollama
# 运行：
#   docker run --rm -p 11434:11434 \
#       -v /opt/ndr/ollama-models:/models:ro \
#       nss-ndr-ollama
#
# 挂载要求：/models/Qwen3-0.6B-Q5_K_M.gguf 必须存在（由部署方提供）
# Modelfile 通过 FROM /models/Qwen3-0.6B-Q5_K_M.gguf 引用挂载的权重。

FROM ollama/ollama:0.5.12

LABEL maintainer="NSS-NDR"
LABEL description="Ollama for NDR local analysis agent (CPU-only, model loaded from external mount)"

# Modelfile：定义 qwen3-ndr 模型（CPU 参数调优）；引用外挂的 GGUF
COPY Modelfile /Modelfile

# CPU 优化入口脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 工具镜像里通常没有 nproc；装一个 procps 用于自动设置线程数
# （ollama 基础镜像基于 Ubuntu，已包含 coreutils，但 nproc 来自 procps）
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
USER ollama

# 健康检查：仅验证 HTTP 端点可达；模型是否加载由 entrypoint 通过 `ollama list` 验证
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:11434/api/tags >/dev/null || exit 1

EXPOSE 11434

# 模型挂载点（运行时由 docker-compose 绑定）
VOLUME ["/models"]

ENTRYPOINT ["/entrypoint.sh"]