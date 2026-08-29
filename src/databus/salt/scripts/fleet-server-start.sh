#!/usr/bin/env bash
# ============================================================
# Fleet Server 启动脚本（Salt 容器 entrypoint）
# 与原始编排定义的 entrypoint/command 逻辑完全一致：
#   1) 若 fleet.enc 不存在 -> enroll 到 Kibana/ES（生成 fleet.enc）
#   2) 以 fleet-server 模式启动 elastic-agent container
# 环境变量：FLEET_ENROLLMENT_TOKEN / ELASTICSEARCH_* / KIBANA_HOST
# ============================================================
set -eu

if [ ! -s /usr/share/elastic-agent/state/fleet.enc ]; then
  echo "Fleet Server: bootstrapping..."
  # 容器内不能用 install（需要 systemd/init.d），改用 enroll --fleet-server-* 直接 bootstrap
  # 注意：9.x 的 --url 指向 Fleet Server 自身（本机 8220），不是 Kibana
  /usr/share/elastic-agent/elastic-agent enroll \
    --url=https://fleet-server:8220 \
    --enrollment-token="${FLEET_ENROLLMENT_TOKEN}" \
    --fleet-server-policy=nss-ndr-fleet-server-policy \
    --fleet-server-es=http://elasticsearch:9200 \
    --fleet-server-port=8220 \
    --certificate-authorities="" \
    --insecure --force --delay-enroll || echo "Enrollment may have already done, continuing"
fi

exec /usr/bin/tini -- /usr/local/bin/docker-entrypoint /usr/bin/tini -- \
  /usr/share/elastic-agent/elastic-agent container --path.home /usr/share/elastic-agent
