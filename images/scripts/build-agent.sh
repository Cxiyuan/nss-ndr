#!/usr/bin/env bash
# ============================================================
# 构建智能体镜像 + 保存为 tar 到 offline/
# - 镜像名：nss-ndr/agent:<版本>（默认 0.1.0，可传参覆盖）
# - 构建上下文：src/agent/
# 用法：./build-agent.sh [版本]
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="$(cd "$ROOT_DIR/../src/agent" && pwd)"
OFFLINE_DIR="$ROOT_DIR/offline"
mkdir -p "$OFFLINE_DIR"

VERSION="${1:-0.1.0}"
IMAGE="nss-ndr/agent:${VERSION}"
TAR="${OFFLINE_DIR}/nss-ndr_agent_${VERSION}.tar"

cd "$ROOT_DIR"

echo "===== Build $IMAGE ====="
docker build \
  --platform linux/amd64 \
  -f "$ROOT_DIR/Dockerfile.agent" \
  -t "$IMAGE" \
  "$AGENT_DIR" 2>&1 | tail -12

echo
echo "===== Verify entrypoint ====="
docker run --rm "$IMAGE" version

echo
echo "===== Save $IMAGE -> $TAR ====="
docker save -o "$TAR" "$IMAGE"

echo
echo "===== Final ====="
ls -lh "$TAR"
