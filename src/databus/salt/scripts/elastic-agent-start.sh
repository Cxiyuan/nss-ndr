#!/usr/bin/env bash
# ============================================================
# Elastic Agent 启动脚本（Salt 容器 entrypoint）
# 与原始编排定义的 entrypoint/command 逻辑完全一致：
#   1) 若 fleet.enc 不存在 -> enroll 到 fleet-server
#   2) 启动 elastic-agent run（从 Fleet 拉取并应用 policy）
# 环境变量：FLEET_ENROLLMENT_TOKEN / FLEET_URL
# ============================================================
set -eu

if [ ! -s /usr/share/elastic-agent/state/fleet.enc ]; then
  echo "Enrolling to fleet-server..."
  /usr/share/elastic-agent/elastic-agent enroll \
    --url=https://fleet-server:8220 \
    --enrollment-token="${FLEET_ENROLLMENT_TOKEN}" \
    --delay-enroll \
    --insecure --force || echo "Enrollment may have already done, continuing"
fi

exec /usr/share/elastic-agent/elastic-agent run --path.home /usr/share/elastic-agent
