# NSS-NDR Zeek 镜像
# 基于 Security Onion 3.1.0 的 so-zeek 镜像（Zeek 8.0.8，含 ja3/ja4/hassh/ICS 等 zkg 插件）
# 瘦身策略：保留引擎与已装插件，覆盖入口与默认配置，其余由 k3s ConfigMap 注入

FROM ghcr.io/security-onion-solutions/so-zeek:3.1.0

LABEL maintainer="NSS-NDR"
LABEL description="Zeek metadata engine for NSS-NDR probe"

# 覆盖入口脚本
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh

# 默认配置与策略脚本（运行时由 ConfigMap 覆盖）
COPY files/local.zeek   /opt/zeek/share/zeek/site/local.zeek
COPY files/node.cfg     /opt/zeek/etc/node.cfg
COPY files/zeekctl.cfg  /opt/zeek/etc/zeekctl.cfg
COPY files/networks.cfg /opt/zeek/etc/networks.cfg
COPY files/policy/securityonion/ /opt/zeek/share/zeek/policy/securityonion/
RUN chown -R 937:937 /opt/zeek/share/zeek/site /opt/zeek/etc /opt/zeek/share/zeek/policy/securityonion

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
