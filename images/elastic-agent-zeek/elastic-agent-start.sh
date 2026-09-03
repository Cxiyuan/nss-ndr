#!/usr/bin/env bash
# ============================================================
# Elastic Agent 启动脚本（Salt 容器 entrypoint）
# 与原始编排定义的 entrypoint/command 逻辑完全一致：
#   1) 若 fleet.enc 不存在 -> enroll 到 fleet-server
#   2) 启动 elastic-agent run（从 Fleet 拉取并应用 policy）
# 环境变量：FLEET_ENROLLMENT_TOKEN / FLEET_URL
# ============================================================
set -eu

ENC=/usr/share/elastic-agent/state/fleet.enc
# 官方 docker-entrypoint 容器初始化在存在 FLEET_ENROLLMENT_TOKEN 时会先写一个
# delay 半成品 fleet.enc(~274B),run 会因它而走 standalone(managed locally)。
# 故 enc 缺失或过小(<500B,视为无效 delay 桩)都重新完整 enroll。
NEED=""
if [ ! -s "$ENC" ]; then NEED=1; fi
if [ -n "$NEED" ]; then
  rm -f "$ENC" "$ENC.lock"
  echo "Enrolling to fleet-server..."
  /usr/share/elastic-agent/elastic-agent enroll \
    --url=https://fleet-server:8220 \
    --enrollment-token="${FLEET_ENROLLMENT_TOKEN}" \
    --insecure --force || echo "Enrollment may have already done, continuing"
elif [ "$(stat -c%s "$ENC" 2>/dev/null || echo 0)" -lt 500 ]; then
  rm -f "$ENC" "$ENC.lock"
  echo "Re-enrolling (invalid fleet.enc)..."
  /usr/share/elastic-agent/elastic-agent enroll \
    --url=https://fleet-server:8220 \
    --enrollment-token="${FLEET_ENROLLMENT_TOKEN}" \
    --insecure --force || echo "Enrollment may have already done, continuing"
fi

exec /usr/share/elastic-agent/elastic-agent run --path.home /usr/share/elastic-agent
