#!/usr/bin/env bash
# ============================================================
# 构建 Salt Master + Salt API 容器镜像 + 保存为 tar 到 offline/
# - 镜像名：nss-ndr/salt-master-api:<版本>（默认 0.1.0，可传参覆盖）
# - 构建上下文：images/（Dockerfile.salt-master-api + salt-master-api/）
# 用法：./build-salt-master-api.sh [版本]
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/offline"
mkdir -p "$OFFLINE_DIR"

VERSION="${1:-0.1.0}"
IMAGE="nss-ndr/salt-master-api:${VERSION}"
TAR="${OFFLINE_DIR}/nss-ndr_salt-master-api_${VERSION}.tar"

cd "$ROOT_DIR"

echo "===== Build $IMAGE ====="
docker build \
  --platform linux/amd64 \
  -f "$ROOT_DIR/Dockerfile.salt-master-api" \
  -t "$IMAGE" \
  "$ROOT_DIR" 2>&1 | tail -12

echo
echo "===== Verify salt-master binary ====="
docker run --rm --entrypoint salt-master "$IMAGE" --version

echo
echo "===== Verify salt-api binary ====="
docker run --rm --entrypoint salt-api "$IMAGE" --version 2>&1 | head -3 || true

echo
echo "===== Save $IMAGE -> $TAR ====="
docker save -o "$TAR" "$IMAGE"

echo
echo "===== Final ====="
ls -lh "$OFFLINE_DIR"/*.tar 2>&1 | head -10