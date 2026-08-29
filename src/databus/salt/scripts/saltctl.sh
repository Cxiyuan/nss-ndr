#!/usr/bin/env bash
# ============================================================================
# 数据总线 Salt 一键操作脚本
# ----------------------------------------------------------------------------
# 自动检测执行方式：
#   - 目标机装有 salt-minion（masterless）-> salt-call --local
#   - 控制机装有 salt-ssh              -> salt-ssh databus
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

if command -v salt-call >/dev/null 2>&1; then
  SALT="salt-call --local"
elif command -v salt-ssh >/dev/null 2>&1; then
  SALT="salt-ssh databus"
else
  echo "[ERROR] 未找到 salt-call / salt-ssh" >&2
  exit 1
fi

case "$CMD" in
  deploy)
    echo "==> 编排部署数据总线（images -> network -> volumes -> ES/Redis -> token -> Kibana -> Fleet -> apps -> verify）"
    $SALT state.apply databus.deploy
    ;;
  apply)
    echo "==> 日常幂等自愈"
    $SALT state.apply databus
    ;;
  status)
    echo "==> 数据总线容器状态"
    docker ps -a --filter "name=nss-ndr-" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    ;;
  verify)
    echo "==> 验证数据流 / ECS 字段"
    $SALT state.apply databus.verify
    ;;
  teardown)
    echo "==> 清理本项目（容器/网络/卷），保留其他业务"
    $SALT state.apply databus.teardown
    ;;
  pillar)
    echo "==> pillar"
    $SALT pillar.items
    ;;
  *)
    echo "用法: $0 {deploy|apply|status|verify|teardown|pillar}"
    exit 1
    ;;
esac
