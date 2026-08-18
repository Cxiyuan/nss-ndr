#!/bin/sh
# NSS-NDR Ollama 容器入口（纯 CPU 优化，外挂 GGUF）
#
# 关键优化：
#   - CUDA_VISIBLE_DEVICES=""  强制 CPU，避开 GPU 检测开销
#   - OLLAMA_NUM_THREADS       默认匹配物理核数（用户可覆盖）
#   - OLLAMA_KEEP_ALIVE=24h    模型驻留内存，避免冷启动
#   - OLLAMA_MAX_LOADED_MODELS=1  单模型探针只加载一个
#
# 模型挂载：docker-compose 把 /opt/ndr/ollama-models 挂到 /models/，
#           期望存在 /models/Qwen3-0.6B-Q5_K_M.gguf（由部署方提供）。

set -e

# ----- CPU 优化环境变量 -----
export OLLAMA_HOST="${OLLAMA_HOST:-0.0.0.0:11434}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-24h}"
export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"

# 默认线程数 = 物理核数；用户可通过 docker-compose env 覆盖
if [ -z "${OLLAMA_NUM_THREADS:-}" ]; then
    if command -v nproc >/dev/null 2>&1; then
        export OLLAMA_NUM_THREADS="$(nproc)"
    else
        export OLLAMA_NUM_THREADS="$(grep -c ^processor /proc/cpuinfo)"
    fi
fi

# 强制 CPU（即使宿主机有 GPU）
export CUDA_VISIBLE_DEVICES=""
export OLLAMA_NOHISTORY="${OLLAMA_NOHISTORY:-1}"

echo "[ollama] 启动配置:"
echo "  HOST             = $OLLAMA_HOST"
echo "  NUM_THREADS      = $OLLAMA_NUM_THREADS"
echo "  KEEP_ALIVE       = $OLLAMA_KEEP_ALIVE"
echo "  MAX_LOADED_MODELS= $OLLAMA_MAX_LOADED_MODELS"
echo "  FORCE_CPU        = yes"

# ----- 检查外挂 GGUF -----
GGUF_PATH="${OLLAMA_GGUF_PATH:-/models/Qwen3-0.6B-Q5_K_M.gguf}"
if [ ! -f "$GGUF_PATH" ]; then
    echo "[ollama] 错误: 未找到 GGUF 文件: $GGUF_PATH"
    echo "[ollama] 请将模型文件放到挂载目录（默认 /opt/ndr/ollama-models/）"
    echo "[ollama] 参考 README.md 准备 GGUF"
    # 不退出，让 healthcheck 失败，由部署方排查
    while true; do sleep 60; done
fi
echo "[ollama] GGUF: $GGUF_PATH ($(du -h "$GGUF_PATH" | cut -f1))"

# ----- 创建/更新模型 -----
MODEL_NAME="qwen3-ndr"
MODEL_EXISTS=0
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL_NAME"; then
    MODEL_EXISTS=1
fi

REBUILD=0
if [ "$MODEL_EXISTS" -eq 0 ]; then
    REBUILD=1
    echo "[ollama] 模型 $MODEL_NAME 不存在，将创建"
elif [ -f /Modelfile ] && [ /Modelfile -nt /root/.ollama/models/manifests/registry.ollama.ai/*/"$MODEL_NAME"/* ] 2>/dev/null; then
    REBUILD=1
    echo "[ollama] Modelfile 已更新，将重建模型"
fi

if [ "$REBUILD" -eq 1 ]; then
    ollama create "$MODEL_NAME" -f /Modelfile
fi

# ----- 预热（可选）-----
if [ "${OLLAMA_WARMUP:-1}" = "1" ]; then
    echo "[ollama] 预热模型（首次推理会更慢）..."
    ollama run "$MODEL_NAME" " " >/dev/null 2>&1 || echo "[ollama] 预热失败（不影响服务）"
fi

echo "[ollama] 启动服务..."
exec ollama serve