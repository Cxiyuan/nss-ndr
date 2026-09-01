# ============================================================================
# 自定义网络 nss-net 192.168.250.0/24
# ----------------------------------------------------------------------------
# docker_network.present 幂等：已存在且配置一致时不动（仅对比，不重建，
# 不中断已连接容器）；配置不一致时重建并重连容器。
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

{% set net = databus.get('network', {}) %}
{% set net_name = net.get('name', 'nss-net') %}
{% set net_subnet = net.get('subnet', '192.168.250.0/24') %}
{# gateway 必须显式给出：与 Docker 实际 IPAM 配置（Subnet+Gateway）完全一致，
   否则 docker_network.present 对比不一致会重建网络并中断已连接容器 #}
{% set net_gateway = net.get('gateway', '192.168.250.1') %}

ensure-{{ net_name }}-present:
  docker_network.present:
    - name: {{ net_name }}
    - driver: bridge
    - ipam_pools:
      - subnet: {{ net_subnet }}
        gateway: {{ net_gateway }}
