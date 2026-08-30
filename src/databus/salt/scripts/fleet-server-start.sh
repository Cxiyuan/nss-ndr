#!/usr/bin/env bash
# ============================================================
# Fleet Server 启动脚本（Salt 容器 entrypoint）
# 交由 elastic-agent container 官方逻辑根据环境变量自动 bootstrap：
#   FLEET_SERVER_ENABLE / FLEET_SERVER_POLICY_ID / FLEET_URL /
#   FLEET_ENROLLMENT_TOKEN / ELASTICSEARCH_* / KIBANA_HOST
# 首次启动：container 模式自动 enroll（含 --install-servers）并拉起 fleet-server；
# 已 enroll（fleet.yml 存在）则直接以 fleet-server 模式运行。
# ============================================================
set -eu

exec /usr/bin/tini -- /usr/local/bin/docker-entrypoint /usr/bin/tini -- \
  /usr/share/elastic-agent/elastic-agent container --path.home /usr/share/elastic-agent
