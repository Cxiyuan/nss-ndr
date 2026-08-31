#!/usr/bin/env bash
# ============================================================================
# 数据总线 Salt 一键操作脚本（salt-master 容器化版）
# ----------------------------------------------------------------------------
# 自 2026-08-31 起，所有 salt 命令通过容器化的 nss-ndr-salt-master-api 执行。
# 目标机不再需要宿主机 salt-minion RPM；只需 Docker + salt-master/salt-minion 两个容器。
# 用法：
#   ./saltctl.sh deploy    # 从零部署 / 完整初始化（编排）
#   ./saltctl.sh apply     # 日常幂等自愈（state.apply databus）
#   ./saltctl.sh status    # 查看本项目容器运行状态
#   ./saltctl.sh verify    # 验证数据流 / ECS 字段
#   ./saltctl.sh teardown  # 清理本项目容器/网络/卷（保留其他业务）
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
  # 兼容：容器未起但宿主机有 salt-minion（过渡期）
  echo "[WARN] ${MASTER_CONTAINER} 不在运行，回退到宿主机 salt-call --local" >&2
  SALT_MASTER="salt-call --local"
else
  echo "[ERROR] 未找到 ${MASTER_CONTAINER} 容器，也无 salt-call 可用" >&2
  exit 1
fi

# 容器内需要用 host network 的 minion_id 显式指定（默认与 minion 配置一致）
case "$CMD" in
  deploy)
    echo "==> 编排部署数据总线（images -> network -> volumes -> salt-master -> salt-minion -> ES -> ... -> apps -> verify）"
    # salt-master 容器必须先于 deploy 启动；此处假设已通过 databus.containers.salt-master-api 起来
    ${SALT_MASTER} salt-run state.orchestrate databus.deploy
    ;;
  apply)
    echo "==> 日常幂等自愈（target=${MINION_ID}）"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply databus
    ;;
  status)
    echo "==> 数据总线容器状态"
    docker ps -a --filter "name=nss-ndr-" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    ;;
  verify)
    echo "==> 验证数据流 / ECS 字段"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply databus.verify
    ;;
  teardown)
    echo "==> 清理本项目（容器/网络/卷），保留其他业务"
    ${SALT_MASTER} salt "${MINION_ID}" state.apply databus.teardown
    ;;
  pillar)
    echo "==> pillar"
    ${SALT_MASTER} salt "${MINION_ID}" pillar.items
    ;;
  *)
    echo "用法: $0 {deploy|apply|status|verify|teardown|pillar}"
    exit 1
    ;;
esac