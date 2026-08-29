#!/usr/bin/env bash
# ============================================================
# 构建带 Zeek Integration 的自定义 elastic-agent 镜像
# - 镜像标签：nss-ndr/elastic-agent-zeek:9.5.2
# - 输出位置：images/offline/nss-ndr_elastic-agent-zeek_9.5.2.tar
# - 不启动容器
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/offline"
ZEEK_INT_DIR="$ROOT_DIR/zeek-integration/zeek-5.0.1"

[[ -d "$ZEEK_INT_DIR" ]] || { echo "[ERROR] $ZEEK_INT_DIR 不存在"; exit 1; }

IMAGE_TAG="nss-ndr/elastic-agent-zeek:9.5.2"
TAR_PATH="$OFFLINE_DIR/$(echo "$IMAGE_TAG" | tr '/:' '__').tar"

cd "$ROOT_DIR"
echo "===== Build context: $ROOT_DIR ====="
ls -la "$ROOT_DIR"

echo
echo "===== [BUILD] $IMAGE_TAG ====="
docker build \
  -f "$ROOT_DIR/Dockerfile.elastic-agent-zeek" \
  -t "$IMAGE_TAG" \
  "$ROOT_DIR" 2>&1 | tail -20

echo
echo "===== [SAVE] $IMAGE_TAG → $TAR_PATH ====="
docker save -o "$TAR_PATH" "$IMAGE_TAG"

echo
echo "===== [VERIFY] 自定义镜像内 Zeek Integration 包位置 ====="
docker run --rm "$IMAGE_TAG" \
  ls /usr/share/elastic-agent/elastic-integrations/packages/zeek-5.0.1/ \
  | head -15

echo
echo "===== 完成 =====" && du -sh "$TAR_PATH"
