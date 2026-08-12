#!/bin/sh
# NSS-NDR elastic-agent 入口（Fleet 容器模式）
#
# 事故复盘（2026-08 部署机 IO 风暴）：elastic-agent 官方容器模式每次启动都会对
# 数据目录执行递归 chown，期间若与采集/清理任务叠加，会把单节点磁盘 IO 打满，
# 导致 containerd CRI 超时、Rancher 等基础设施连锁崩溃。
#
# 防护措施：
#   1) 以空闲 IO 优先级（ionice -c3）+ 低 CPU 优先级（nice 19）预置权限，
#      只处理容器内数据目录（量小），失败不阻塞启动；
#   2) exec 官方入口时整体继承低 IO/CPU 优先级，即使官方 chown 仍执行，
#      其磁盘压力也不会抢占业务 IO。

set -e

if command -v ionice >/dev/null 2>&1; then
    IONICE="ionice -c3"
else
    IONICE=""
fi
if command -v nice >/dev/null 2>&1; then
    NICE="nice -n 19"
else
    NICE=""
fi

# 窄范围权限兜底（镜像内数据目录，规模小）
$IONICE $NICE chown -R elastic-agent:elastic-agent /usr/share/elastic-agent/data 2>/dev/null || true

# 官方 9.x 镜像二进制实际位于 /usr/share/elastic-agent/elastic-agent（软链到 data 目录）；
# 部分版本同时提供 /usr/bin/elastic-agent，做兼容检测。
AGENT_BIN="/usr/share/elastic-agent/elastic-agent"
if [ ! -x "$AGENT_BIN" ]; then
    AGENT_BIN="/usr/bin/elastic-agent"
fi
if [ ! -x "$AGENT_BIN" ]; then
    echo "fatal: elastic-agent binary not found" >&2
    exit 1
fi

# 官方容器模式入口：elastic-agent container
exec $IONICE $NICE "$AGENT_BIN" container "$@"
