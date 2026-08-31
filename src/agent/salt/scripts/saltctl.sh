#!/usr/bin/env bash
# ============================================================================
# 智能体 Salt 一键操作脚本（salt-master 容器化版）
# ----------------------------------------------------------------------------
# 自 2026-08-31 起，所有 salt 命令通过容器化的 nss-ndr-salt-master-api 执行。
# 本脚本对 src/databus/salt/scripts/saltctl.sh 的 agent 子集：
#   智能体独立的 agent.* states 由 master 容器通过 salt-call 调度
# 用法：
#   ./saltctl.sh deploy    # 从零部署 / 完整初始化（编排）
#   ./saltctl.sh apply     # 日常幂等自愈（state.apply agent）
#   ./saltctl.sh status    # 容器状态
#   ./saltctl.sh verify    # 验证消费组 / 容器日志
#   ./saltctl.sh teardown  # 清理智能体（保留数据总线）
#   ./saltctl.sh pillar    # 查看 pillar
# ============================================================================
set -euo pipefail

CMD="${1:-help}"

MASTER_CONTAINER="${NSS_SALT_MASTER_CONTAINER:-nss-ndr-salt-master-api}"
MINION_ID="${NSS_SALT_MINION_ID:-nss-ai-agent-minion}"

# 检测执行方式：master 容器是否在跑
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${MASTER_CONTAINER}"; then
  SALT_MASTER="docker exec ${MASTER_CONTAINER}"
elif command -v salt-call >/dev/null 2>&1; then
  echo "[WARN] ${MASTER_CONTAINER} 不在运行，回退到宿主机 salt-call --local" >&2
  SALT_MASTER="salt-call --local"
else
  echo "[ERROR] 未找到 ${MASTER_CONTAINER} 容器，也无 salt-call 可用" >&2
  exit 1
fi

case "$CMD" in
  deploy)
    echo "==> 编排部署智能体（images -> configs -> 预检 databus -> setup -> 容器 -> verify）"
    ${SALT_MASTER} salt-run state.orchestrate agent.deploy
    ;;
  apply)
    echo "==> 日常幂等自愈"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply agent
    ;;
  status)
    echo "==> 智能体容器状态"
    docker ps -a --filter "name=nss-ndr-agent" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    ;;
  verify)
    echo "==> 验证消费组 / 容器日志"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply agent.verify
    ;;
  teardown)
    echo "==> 清理智能体（保留数据总线）"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply agent.teardown
    ;;
  pillar)
    echo "==> agent pillar"
    ${SALT_MASTER} salt "${MINION_ID}" pillar.get agent
    ;;
  *)
    echo "用法: $0 {deploy|apply|status|verify|teardown|pillar}"
    exit 1
    ;;
esac