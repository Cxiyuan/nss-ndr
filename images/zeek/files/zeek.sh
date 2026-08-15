#!/bin/bash
# NSS-NDR Zeek 入口

set -e

CONF=/opt/so/conf

# 从 ConfigMap（挂载于 /opt/so/conf）同步配置与策略
[ -f "$CONF/local.zeek" ]   && cp -f "$CONF/local.zeek"   /opt/zeek/share/zeek/site/local.zeek
[ -f "$CONF/node.cfg" ]     && cp -f "$CONF/node.cfg"     /opt/zeek/etc/node.cfg
[ -f "$CONF/zeekctl.cfg" ]  && cp -f "$CONF/zeekctl.cfg"  /opt/zeek/etc/zeekctl.cfg
[ -f "$CONF/networks.cfg" ] && cp -f "$CONF/networks.cfg" /opt/zeek/etc/networks.cfg
[ -f "$CONF/bpf" ] && cp -f "$CONF/bpf" /opt/zeek/etc/bpf
# JA4 选项（对齐 SO：覆盖 ja4 包内 config.zeek）
[ -f "$CONF/config.zeek" ] && cp -f "$CONF/config.zeek" /opt/zeek/share/zeek/site/packages/ja4/config.zeek
if [ -d "$CONF/policy/securityonion" ]; then
  mkdir -p /opt/zeek/share/zeek/policy/securityonion
  cp -rf "$CONF/policy/securityonion/." /opt/zeek/share/zeek/policy/securityonion/
fi
if [ -d "$CONF/policy/cve-2020-0601" ]; then
  mkdir -p /opt/zeek/share/zeek/policy/cve-2020-0601
  cp -rf "$CONF/policy/cve-2020-0601/." /opt/zeek/share/zeek/policy/cve-2020-0601/
fi
if [ -d "$CONF/policy/intel" ]; then
  mkdir -p /opt/zeek/share/zeek/policy/intel
  cp -rf "$CONF/policy/intel/." /opt/zeek/share/zeek/policy/intel/
fi
chown -R 937:937 /opt/zeek/share/zeek/site /opt/zeek/etc /opt/zeek/share/zeek/policy/securityonion /opt/zeek/share/zeek/policy/cve-2020-0601 /opt/zeek/share/zeek/policy/intel

# 抓包能力（AF_PACKET 需要）
setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/capstats

# 确保目录就绪
mkdir -p /nsm/zeek/logs /nsm/zeek/spool /nsm/zeek/extracted/complete
chown -R 937:937 /nsm/zeek

# 启动前归档上次运行的日志文件：非正常重启（pod 重建/进程被杀）时旧文件未轮转，
# filestream 的 offset registry 与重建后的文件状态冲突会卡住采集；
# 归档后 zeek 创建全新日志文件，filestream 识别为新文件从头读取。
if [ -d /nsm/zeek/logs/current ] && compgen -G "/nsm/zeek/logs/current/*.log" >/dev/null; then
  ARCHIVE_DIR="/nsm/zeek/logs/archive-$(date +%Y-%m-%d-%H%M%S)"
  mkdir -p "$ARCHIVE_DIR"
  mv /nsm/zeek/logs/current/*.log "$ARCHIVE_DIR/" 2>/dev/null || true
  chown -R 937:937 "$ARCHIVE_DIR"
  echo "已归档上次运行日志到 $ARCHIVE_DIR"
fi

# 部署并运行 Zeek（node.cfg / local.zeek 由 ConfigMap 挂载）
runuser zeek -c '/opt/zeek/bin/zeekctl deploy'

trap "runuser zeek -c '/opt/zeek/bin/zeekctl stop'" SIGTERM
sleep infinity &
wait $!
