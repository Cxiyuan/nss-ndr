#!/bin/bash
# NSS-NDR Suricata 入口
# 环境变量：
#   INTERFACE   抓包接口（必填，如 bond0 / eth1）
#   EXTRA_ARGS  附加 suricata 参数（可选）

set -e

CONF=/opt/so/conf

# 从 ConfigMap（挂载于 /opt/so/conf）同步配置
if [ -f "$CONF/suricata.yaml" ]; then
  cp -f "$CONF/suricata.yaml" /etc/suricata/suricata.yaml
fi
[ -f "$CONF/threshold.conf" ] && cp -f "$CONF/threshold.conf" /etc/suricata/threshold.conf
[ -f "$CONF/bpf" ] && cp -f "$CONF/bpf" /etc/suricata/bpf
# 规则目录由 detections 服务管理（共享 hostPath /opt/so/rules/suricata）
chown -R 940:940 /etc/suricata/rules

AFPACKET=
if [ -n "$INTERFACE" ]; then
  AFPACKET="--af-packet=$INTERFACE"
fi

# 清理旧 PID，确保可启动
mkdir -p /var/run/suricata
chown 940:940 /var/run/suricata
chmod 770 /var/run/suricata
rm -rf /var/run/suricata.pid

# pcap-log 全包目录（对应 suricata.yaml 的 pcap-log.dir=/nsm/suripcap）
# mode: multi 时每个 af-packet worker 一个子目录（/nsm/suripcap/N，与 SO 3.1.0 一致）
mkdir -p /nsm/suripcap
THREADS=$(awk '/^af-packet:/{f=1} f && /threads:/{gsub(/[^0-9]/,""); print; exit}' /etc/suricata/suricata.yaml)
THREADS=${THREADS:-1}
for i in $(seq 1 "$THREADS"); do
  mkdir -p "/nsm/suripcap/$i"
done
chown 940:940 /nsm/suripcap /nsm/suripcap/* 2>/dev/null || true

exec /opt/suricata/bin/suricata \
  -c /etc/suricata/suricata.yaml \
  $AFPACKET \
  --user=940 --group=940 \
  --pidfile /var/run/suricata.pid \
  -F /etc/suricata/bpf \
  $EXTRA_ARGS
