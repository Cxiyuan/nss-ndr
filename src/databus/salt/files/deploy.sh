#!/usr/bin/env bash
# ============================================================
# NSS-NDR masterless 部署编排（salt-call 分阶段调用，幂等）
# 适用：
#   - 首次部署（fresh init）：从零创建网络/卷/镜像/容器/策略/集成
#   - 日常自愈：所有状态均为幂等，重复执行仅做差异修复
#   - 开机自启：由 /etc/systemd/system/nss-ndr-bootstrap.service 调用
# 前置：docker、salt-masterless、/srv/salt、/srv/pillar 已就绪
# ============================================================
set -uo pipefail

LOG=/tmp/nss-ndr-deploy.log
: > "$LOG"

ENV_FILE=/etc/nss-ndr/.env
ES_PASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)

# 单阶段执行：失败打印尾部日志后继续（盐状态幂等，常见失败为"已就绪"）
run() {
  local stage="$1"
  echo "==> $stage" | tee -a "$LOG"
  if ! timeout 900 salt-call --local state.apply "$stage" >>"$LOG" 2>&1; then
    echo "    [WARN] $stage 失败，查看 $LOG 末尾" | tee -a "$LOG"
    tail -20 "$LOG"
  fi
}

wait_http() {
  local url="$1" who="$2" i=0
  while [ $i -lt 300 ]; do
    if curl -fsS -u "elastic:${ES_PASS:-changeme}" "$url" >/dev/null 2>&1; then
      echo "    ✓ $who 就绪"; return 0
    fi
    sleep 5; i=$((i+5))
  done
  echo "    [!] $who 等待超时，继续后续阶段（可能被幂等状态修复）"
  return 1
}

echo "==== NSS-NDR 部署开始 $(date) ====" | tee -a "$LOG"

# ---- 基础 ----
run databus.images
run databus.network
run databus.volumes
run databus.configs
run databus.bootstrap
run databus.autostart

# ---- 数据总线（先 ES + Redis）----
run databus.containers.elasticsearch
run databus.containers.redis
wait_http http://localhost:9200/_cluster/health "Elasticsearch"

# ---- Kibana ----
run databus.containers.kibana
wait_http http://localhost:5601/api/status "Kibana"

# ---- Fleet 初始化（policies/keys/integration）----
run databus.fleet-setup

# ---- 业务容器 ----
run databus.containers.fleet-server
run databus.containers.elastic-agent
run databus.containers.logstash
run databus.containers.zeek
run databus.containers.agent

# ---- 验证 ----
run databus.verify

# ---- 智能体 ----
run agent.images
run agent.configs
run agent.bootstrap
run agent.setup
run agent.containers.agent
run agent.verify

echo "==== NSS-NDR 部署完成 $(date) ====" | tee -a "$LOG"
