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
#   容器启动瞬间宿主上可能正有其它 nftables 变更（Docker 自身、并发容器），
#   失败时重试几次更稳。失败会打印 iptables 的真实 stderr，便于排查。
#
# 实现注意（踩过的坑）：
#   add_rule 用 "$@" 接收 iptables 参数，不要拼成一整个字符串再靠 IFS 分词 ——
#   调用点为了让 $SUBNETS 按逗号切分把 IFS 设成了 ','，此时空格不再分词，
#   整条规则会被当成一个参数传下去，报
#   「interface name ` tun0 -d ...' must be shorter than 16 characters」。
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

# $@ = 传给 iptables 的参数（不要拼字符串）
add_rule() {
    i=0
    while [ "$i" -lt "$RETRIES" ]; do
        i=$((i + 1))
        if iptables -C DOCKER-USER "$@" 2>/dev/null; then
            echo "[entrypoint] iptables 规则已存在: $*"
            return 0
        fi
        if err="$(iptables -I DOCKER-USER 1 "$@" 2>&1)"; then
            echo "[entrypoint] 已添加 iptables 规则: $*"
            return 0
        fi
        echo "[entrypoint] 第 $i/$RETRIES 次添加失败: $* -> ${err:-unknown}" >&2
        if [ "$i" -lt 3 ]; then sleep 1; else sleep 2; fi
    done
    echo "[entrypoint] WARN: 添加 iptables 规则最终失败: $*" >&2
    return 1
}

if [ -n "$SUBNETS" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for sn in $SUBNETS; do
        IFS="$OLD_IFS"                 # 立刻还原，避免影响后续命令的分词
        [ -n "$sn" ] || { IFS=','; continue; }
        add_rule -i tun0 -d "$sn" -j ACCEPT
        add_rule -s "$sn" -o tun0 -j ACCEPT
        IFS=','
    done
    IFS="$OLD_IFS"
fi

exec easytier-core "$@"
