# NSS-NDR Suricata 镜像
# 基于 Security Onion 3.1.0 的 so-suricata 镜像（Suricata 8.0.5，含 fx-libpcap 优化）
# 瘦身策略：保留引擎与依赖，覆盖入口与默认配置，其余由 k3s ConfigMap 注入

FROM ghcr.io/security-onion-solutions/so-suricata:3.1.0

LABEL maintainer="NSS-NDR"
LABEL description="Suricata NIDS + pcap-log for NSS-NDR probe"

# 覆盖入口脚本
COPY files/so-suricata.sh /usr/local/sbin/so-suricata.sh
RUN chmod +x /usr/local/sbin/so-suricata.sh

# 默认配置模板（运行时由 ConfigMap 覆盖 /etc/suricata/suricata.yaml）
COPY files/suricata.yaml /etc/suricata/suricata.yaml
COPY files/threshold.conf /etc/suricata/threshold.conf

# 默认空规则集（M0 不带任何规则）
RUN mkdir -p /etc/suricata/rules && \
    touch /etc/suricata/rules/all-rulesets.rules && \
    chown -R 940:940 /etc/suricata/rules

ENTRYPOINT ["/usr/local/sbin/so-suricata.sh"]
