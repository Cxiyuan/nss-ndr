#!/usr/bin/env bash
# ============================================================
# 拉取数据总线所需全部基础镜像 → 保存为 tar 到 images/offline/
# 不会启动容器
# ============================================================
set -euo pipefail

OFFLINE_DIR="$(cd "$(dirname "$0")/.." && pwd)/offline"
mkdir -p "$OFFLINE_DIR"

# 镜像清单（与 docker-compose.yaml 对齐）
IMAGES=(
  "docker.elastic.co/elasticsearch/elasticsearch:9.5.2"
  "docker.elastic.co/kibana/kibana:9.5.2"
  "docker.elastic.co/logstash/logstash:9.5.2"
  "docker.elastic.co/elastic-agent/elastic-agent:9.5.2"
  "zeek/zeek:8.2.2"
  "redis:8.10.1"
)

PULL_LOG="/tmp/pull-base-images.log"
: > "$PULL_LOG"

for img in "${IMAGES[@]}"; do
  img_file=$(echo "$img" | tr '/:' '__')
  tar_path="${OFFLINE_DIR}/${img_file}.tar"

  if [[ -f "$tar_path" ]]; then
    echo "[SKIP] $img 已存在 ${tar_path##*/}" | tee -a "$PULL_LOG"
    continue
  fi

  echo "[PULL] $img" | tee -a "$PULL_LOG"
  if docker pull "$img" >> "$PULL_LOG" 2>&1; then
    echo "[SAVE] → ${tar_path##*/}" | tee -a "$PULL_LOG"
    docker save -o "$tar_path" "$img" >> "$PULL_LOG" 2>&1
  else
    echo "[FAIL] $img 拉取失败，详见 $PULL_LOG" | tee -a "$PULL_LOG"
  fi
done

echo
echo "===== 镜像清单 =====" && du -sh "$OFFLINE_DIR"/*.tar 2>/dev/null
echo
echo "===== 完整性 =====" && ls -lh "$OFFLINE_DIR"
