#!/usr/bin/env bash
# ============================================================================
# 智能体 Salt 一键操作脚本（masterless）
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
SALT="salt-call --local"

case "$CMD" in
  deploy)
    echo "==> 编排部署智能体（images -> configs -> 预检 databus -> setup -> 容器 -> verify）"
    $SALT state.apply agent.deploy
    ;;
  apply)
    echo "==> 日常幂等自愈"
    $SALT state.apply agent
    ;;
  status)
    echo "==> 智能体容器状态"
    docker ps -a --filter "name=nss-ndr-agent" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    ;;
  verify)
    echo "==> 验证消费组 / 容器日志"
    $SALT state.apply agent.verify
    ;;
  teardown)
    echo "==> 清理智能体（保留数据总线）"
    $SALT state.apply agent.teardown
    ;;
  pillar)
    echo "==> agent pillar"
    $SALT pillar.get agent
    ;;
  *)
    echo "用法: $0 {deploy|apply|status|verify|teardown|pillar}"
    exit 1
    ;;
esac
