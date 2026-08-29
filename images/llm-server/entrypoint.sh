#!/bin/sh
# ============================================================================
# llama-server 启动入口：把容器 ENV 映射为 llama-server 参数。
# 支持环境变量见 Dockerfile ENV 与 README「运行配置」一节。
# ============================================================================
set -eu

BIN=/usr/local/bin/llama-server
MODEL="${LLM_MODEL:-/models/model.gguf}"

if [ ! -f "$MODEL" ]; then
    echo "ERROR: GGUF 模型文件不存在：$MODEL（挂载 /models 或设置 LLM_MODEL）" >&2
    exit 1
fi

set -- \
    --model "$MODEL" \
    --host "${LLM_HOST:-0.0.0.0}" \
    --port "${LLM_PORT:-8080}" \
    --ctx-size "${LLM_CONTEXT_SIZE:-32768}" \
    --parallel "${LLM_PARALLEL:-1}" \
    --batch-size "${LLM_BATCH_SIZE:-2048}" \
    --ubatch-size "${LLM_UBATCH_SIZE:-512}" \
    --cache-type-k "${LLM_CACHE_TYPE_K:-q8_0}" \
    --cache-type-v "${LLM_CACHE_TYPE_V:-q8_0}" \
    --n-gpu-layers 0

if [ -n "${LLM_ALIAS:-}" ]; then
    set -- "$@" --alias "$LLM_ALIAS"
fi

if [ -n "${LLM_THREADS:-}" ]; then
    set -- "$@" --threads "$LLM_THREADS" --threads-batch "$LLM_THREADS"
fi

if [ -n "${LLM_API_KEY:-}" ]; then
    set -- "$@" --api-key "$LLM_API_KEY"
fi

# 允许追加任意参数（如 --mlock / --numa distribute / --no-mmap）
# shellcheck disable=SC2086
if [ -n "${LLM_EXTRA_ARGS:-}" ]; then
    set -- "$@" $LLM_EXTRA_ARGS
fi

echo "llama.cpp commit: $(cat /usr/local/share/llama.cpp.commit 2>/dev/null || echo unknown)"
exec "$BIN" "$@"
