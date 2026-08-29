#!/usr/bin/env bash
# ============================================================
# Zeek 启动脚本（Salt 容器 entrypoint）
# 与原始编排定义的 command 逻辑一致：
#   export PATH -> exec zeek -i $ZEEK_INTERFACE local.zeek
# 环境变量：ZEEK_INTERFACE（由 pillar 注入，默认 eth0）
# ============================================================
set -e
export PATH=/usr/local/zeek/bin:$PATH
exec zeek -i "${ZEEK_INTERFACE:-eth0}" /opt/zeek/share/zeek/site/local.zeek
