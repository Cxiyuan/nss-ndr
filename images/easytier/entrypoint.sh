#!/bin/sh
# ============================================================================
# EasyTier 容器 entrypoint 包装
# ----------------------------------------------------------------------------
# 在启动 easytier-core 之前，补齐「子网代理」所需的 iptables 放行规则。
#
# 为什么需要：
#   EasyTier 做子网代理时，虚拟网内节点发来的包要经本机转发到目标网段
#   （如 docker 网 192.168.250.0/24，数据总线的 ES/Kibana/Redis/LLM 都在里面）。
#   但 Docker 把宿主 FORWARD 链策略设为 DROP，且只为 docker 网络之间加了放行
#   —— 从 tun0 进 docker 网的【新建连接】会被丢掉。
#   实测症状：ICMP 通（连 1400 字节大包都通），但 TCP 一律不通
#   （连宿主自己的 22 端口都不通）；补规则后 TCP 正常。
#
# 为什么由容器自己加规则：
#   本容器是 network_mode=host + NET_ADMIN，iptables 操作的就是【宿主】规则；
#   而 salt-minion 跑在独立 netns 里，改不到宿主 iptables。容器随宿主重启
#   自动拉起（restart=unless-stopped），规则也随之自动补齐，不需要额外的
#   持久化机制，也不依赖在服务器上手工执行命令。
#
# 为什么用 DOCKER-USER 链：
#   Docker 保证该链在 FORWARD 之前被求值，且不会随 docker/网络重载被清掉，
#   是官方推荐的用户自定义规则位置。规则用 -C 判重后 -I 插入，幂等。
#
# 环境变量：
#   EASYTIER_PROXY_SUBNETS  逗号分隔的子网代理网段（由 salt pillar
#                           databus.easytier.proxy_networks 渲染下发）
# ============================================================================
set -u

SUBNETS="${EASYTIER_PROXY_SUBNETS:-}"
if [ -n "$SUBNETS" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for sn in $SUBNETS; do
        [ -n "$sn" ] || continue
        for r in "-i tun0 -d $sn -j ACCEPT" "-s $sn -o tun0 -j ACCEPT"; do
            if iptables -C DOCKER-USER $r 2>/dev/null; then
                echo "[entrypoint] iptables 规则已存在: $r"
            elif iptables -I DOCKER-USER 1 $r 2>/dev/null; then
                echo "[entrypoint] 已添加 iptables 规则: $r"
            else
                echo "[entrypoint] WARN: 添加 iptables 规则失败: $r" >&2
            fi
        done
    done
    IFS="$OLD_IFS"
fi

exec easytier-core "$@"
