#!/usr/bin/env bash
# ============================================================
# 构建自定义 zeek 镜像 + 保存为 tar 到 offline/
# - 镜像名：nss-ndr/zeek:8.2.2
# - 删除原油 zeek/zeek:8.2.2 tar
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OFFLINE_DIR="$ROOT_DIR/offline"
mkdir -p "$OFFLINE_DIR"

CUSTOM_IMAGE="nss-ndr/zeek:8.2.2"
CUSTOM_TAR="${OFFLINE_DIR}/$(echo "$CUSTOM_IMAGE" | tr '/:' '__').tar"
ORIG_TAR="${OFFLINE_DIR}/zeek_zeek_8.2.2.tar"

cd "$ROOT_DIR"

echo "===== Build $CUSTOM_IMAGE ====="
docker build \
  -f "$ROOT_DIR/Dockerfile.zeek-custom" \
  -t "$CUSTOM_IMAGE" \
  "$ROOT_DIR" 2>&1 | tail -8

echo
echo "===== Save $CUSTOM_IMAGE -> $CUSTOM_TAR ====="
docker save -o "$CUSTOM_TAR" "$CUSTOM_IMAGE"

echo
echo "===== Remove original zeek/zeek:8.2.2 tar ====="
if [[ -f "$ORIG_TAR" ]]; then
  echo "Removing: $ORIG_TAR"
  find "$ORIG_TAR" -type f -delete
  find "$ORIG_TAR" -type d -empty -delete 2>/dev/null
  echo "OK"
else
  echo "Not found: $ORIG_TAR"
fi

echo
echo "===== Verify custom image ====="
docker run --rm --entrypoint head "$CUSTOM_IMAGE" -n 3 /usr/local/zeek/share/zeek/site/local.zeek

echo
echo "===== Final ====="
ls -lh "$OFFLINE_DIR"/*.tar 2>&1 | head -10
