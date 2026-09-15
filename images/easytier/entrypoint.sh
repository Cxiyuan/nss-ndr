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
# 为什么要重试：
#   容器启动的同一时刻，Docker 自己也在改 nftables（创建容器时的规则变更），
#   两边抢 nftables 锁会导致我们的 iptables 调用偶发失败 —— 实测【每次启动
#   都失败、而容器起来后 docker exec 进去执行同样的命令却成功】。故这里做
#   指数退避重试，并在失败时打印真实错误，便于排查。
#
# 为什么用 DOCKER-USER 链：
#   Docker 保证该链在 FORWARD 之前被求值，且不会随 docker/网络重载被清掉，
#   是官方推荐的用户自定义规则位置。规则用 -C 判重后 -I 插入，幂等。
#
# 环境变量：
#   EASYTIER_PROXY_SUBNETS  逗号分隔的子网代理网段（由 salt pillar
#                           databus.easytier.proxy_networks 渲染下发）
#   EASYTIER_IPT_RETRIES    重试次数（默认 10）
# ============================================================================
set -u

SUBNETS="${EASYTIER_PROXY_SUBNETS:-}"
RETRIES="${EASYTIER_IPT_RETRIES:-10}"

add_rule() {
    rule="$1"
    i=0
    while [ "$i" -lt "$RETRIES" ]; do
        i=$((i + 1))
        if iptables -C DOCKER-USER $rule 2>/dev/null; then
            echo "[entrypoint] iptables 规则已存在: $rule"
            return 0
        fi
        if err="$(iptables -I DOCKER-USER 1 $rule 2>&1)"; then
            echo "[entrypoint] 已添加 iptables 规则: $rule"
            return 0
        fi
        echo "[entrypoint] 第 $i/$RETRIES 次添加失败: $rule -> ${err:-unknown}" >&2
        if [ "$i" -lt 3 ]; then sleep 1; else sleep 2; fi
    done
    echo "[entrypoint] WARN: 添加 iptables 规则最终失败: $rule" >&2
    return 1
}

if [ -n "$SUBNETS" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for sn in $SUBNETS; do
        [ -n "$sn" ] || continue
        add_rule "-i tun0 -d $sn -j ACCEPT"
        add_rule "-s $sn -o tun0 -j ACCEPT"
    done
    IFS="$OLD_IFS"
fi

exec easytier-core "$@"
