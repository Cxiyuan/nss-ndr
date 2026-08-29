#!/usr/bin/env bash
# ============================================================
# 下载本地边缘模型 GGUF 到 offline/models/（供 Salt / docker run 挂载）
# - 默认模型：Salesforce/xLAM-2-1b-fc-r-gguf 的 Q4_K_M（约 0.99GB，设计文档 §2/§4/§8）
# 用法：./fetch-model.sh [模型文件] [HF 仓库]
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MODEL_DIR="$ROOT_DIR/offline/models"
mkdir -p "$MODEL_DIR"

HF_REPO="${2:-Salesforce/xLAM-2-1b-fc-r-gguf}"
MODEL_FILE="${1:-xLAM-2-1B-fc-r-Q4_K_M.gguf}"
URL="https://huggingface.co/${HF_REPO}/resolve/main/${MODEL_FILE}"
DEST="$MODEL_DIR/$MODEL_FILE"

if [ -s "$DEST" ]; then
    echo "已存在：$DEST（$(du -h "$DEST" | cut -f1)），跳过下载"
    exit 0
fi

echo "===== Download $URL ====="
curl -fL --retry 3 --progress-bar -o "$DEST" "$URL"

echo
echo "===== SHA-256 ====="
shasum -a 256 "$DEST"
ls -lh "$DEST"
