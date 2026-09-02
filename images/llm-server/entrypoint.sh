#!/bin/sh
# ============================================================================
# llama-server 启动入口：把容器 ENV 映射为 llama-server 参数。
# 关键设计：
#   - 线程数 / ctx-size 按比例（默认 0.75）相对宿主机 CPU 实时计算，
#     不写死值，避免换硬件环境数值不适配。
#   - LLM_THREADS_RATIO  * nproc            = llama-server --threads
#   - LLM_CONTEXT_RATIO * LLM_CONTEXT_SIZE  = 实际 ctx-size（写入 --ctx-size）
#   - 其余 ENV 透传。
# ============================================================================
set -eu

BIN=/usr/local/bin/llama-server
MODEL="${LLM_MODEL:-/models/model.gguf}"

if [ ! -f "$MODEL" ]; then
    echo "ERROR: GGUF 模型文件不存在：$MODEL（挂载 /models 或设置 LLM_MODEL）" >&2
    exit 1
fi

# 宿主机 CPU 核数（容器内可读 /proc/cpuinfo）；nproc 命令可能在 alpine 极简镜像缺失。
NPC=$(awk '/^processor[[:space:]]*:/ {n++} END {print n+0}' /proc/cpuinfo 2>/dev/null)
if [ -z "$NPC" ] || [ "$NPC" -lt 1 ]; then
    NPC=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

# 线程比例（默认 0.75，相对宿主机 CPU 核数）。
THREAD_RATIO="${LLM_THREADS_RATIO:-0.75}"
# 上限：宿主机 CPU 核数 × ratio，最低 1。
THREADS=$(awk -v npc="$NPC" -v r="$THREAD_RATIO" 'BEGIN {t=int(npc*r); if (t<1) t=1; print t}')
export LLM_THREADS="$THREADS"

# 上下文窗口比例（默认 0.75，相对配置的 LLM_CONTEXT_SIZE）。
CTX_RATIO="${LLM_CONTEXT_RATIO:-0.75}"
BASE_CTX="${LLM_CONTEXT_SIZE:-4096}"
CTX_SIZE=$(awk -v c="$BASE_CTX" -v r="$CTX_RATIO" 'BEGIN {t=int(c*r); if (t<512) t=512; print t}')
LLM_CONTEXT_SIZE="$CTX_SIZE"

set -- \
    --model "$MODEL" \
    --host "${LLM_HOST:-0.0.0.0}" \
    --port "${LLM_PORT:-8080}" \
    --ctx-size "$LLM_CONTEXT_SIZE" \
    --threads "$LLM_THREADS" \
    --threads-batch "$LLM_THREADS" \
    --parallel "${LLM_PARALLEL:-2}" \
    --batch-size "${LLM_BATCH_SIZE:-1024}" \
    --ubatch-size "${LLM_UBATCH_SIZE:-256}" \
    --cache-type-k "${LLM_CACHE_TYPE_K:-q8_0}" \
    --cache-type-v "${LLM_CACHE_TYPE_V:-q8_0}" \
    --n-gpu-layers 0

if [ -n "${LLM_ALIAS:-}" ]; then
    set -- "$@" --alias "$LLM_ALIAS"
fi

if [ -n "${LLM_API_KEY:-}" ]; then
    set -- "$@" --api-key "$LLM_API_KEY"
fi

# 允许追加任意参数
if [ -n "${LLM_EXTRA_ARGS:-}" ]; then
    set -- "$@" $LLM_EXTRA_ARGS
fi

echo "[llm-entrypoint] nproc=${NPC} threads=${LLM_THREADS} (ratio=${THREAD_RATIO}) ctx_size=${LLM_CONTEXT_SIZE} (base=${BASE_CTX} ratio=${CTX_RATIO})"
echo "llama.cpp commit: $(cat /usr/local/share/llama.cpp.commit 2>/dev/null || echo unknown)"
exec "$BIN" "$@"
