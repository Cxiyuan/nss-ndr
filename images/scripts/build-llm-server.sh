#!/usr/bin/env bash
# ============================================================
# 构建 LLM Server 镜像 + 保存为 tar 到 offline/
# - 镜像名：nss-ndr/llm-server:<版本>（默认 0.1.0，可传参覆盖）
# - 构建上下文：images/（Dockerfile.llm-server + llm-server/）
# 用法：./build-llm-server.sh [版本]
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/offline"
mkdir -p "$OFFLINE_DIR"

VERSION="${1:-0.1.0}"
IMAGE="nss-ndr/llm-server:${VERSION}"
TAR="${OFFLINE_DIR}/nss-ndr_llm-server_${VERSION}.tar"

cd "$ROOT_DIR"

echo "===== Build $IMAGE ====="
docker build \
  --platform linux/amd64 \
  -f "$ROOT_DIR/Dockerfile.llm-server" \
  -t "$IMAGE" \
  "$ROOT_DIR" 2>&1 | tail -12

echo
echo "===== Verify llama-server ====="
docker run --rm --entrypoint /usr/local/bin/llama-server "$IMAGE" --version

echo
echo "===== Verify CPU dispatch (AVX512) ====="
docker run --rm --entrypoint /usr/local/bin/llama-server "$IMAGE" --verbose-prompt 2>&1 | head -5 || true

echo
echo "===== Save $IMAGE -> $TAR ====="
docker save -o "$TAR" "$IMAGE"

echo
echo "===== Final ====="
ls -lh "$TAR"
