# ============================================================================
# EasyTier 容器（nss-ndr-easytier）—— P2P 虚拟组网
# ----------------------------------------------------------------------------
# 作用：把本机接入 EasyTier 虚拟网络，让虚拟网内的其他节点（智能体侧/运维侧）
#       可以访问本机服务，或让本机访问虚拟网内其他节点。
#
# 为什么必须是 host 网络 + 特权能力：
#   EasyTier 通过创建 TUN 接口（默认 easytier0）实现组网。TUN 是【网络命名空间
#   级】资源 —— 放在容器自己的 netns 里，宿主机和其他容器都走不到那条虚拟网。
#   所以必须：
#     network_mode: host                 （共享宿主 netns，TUN 建在宿主上）
#     cap_add: NET_ADMIN, NET_RAW        （建接口/改路由/原始套接字）
#     devices: /dev/net/tun              （TUN 字符设备，宿主需 modprobe tun）
#   宿主机前置条件（实测已满足）：/dev/net/tun 存在、net.ipv4.ip_forward=1。
#
# 安全性要点：
#   - 默认【不做子网代理】：不会把本机 LAN（172.16.196.0/24）暴露给虚拟网。
#     需要暴露时显式配 proxy_networks（pillar），这是有安全含义的操作。
#   - relay_network_whitelist 控制是否为【其他虚拟网】转发流量。默认配成本网络名
#     （只为本网络转发），留空则不为任何其他网络转发。
#   - 虚拟网段默认 10.126.126.0/24（dhcp 模式）或显式 ipv4。
#
# 镜像来源：官方只在 Docker Hub（服务器连不上），由 CI 转发到 GHCR
#           （见 images/Dockerfile.easytier），故 image 走 ghcr.nju.edu.cn。
# ----------------------------------------------------------------------------
# 参数全部来自 pillar databus.easytier（密钥不入仓库）：见 pillar.example
# ============================================================================

include:
  - databus.network
  - databus.images

{% from "databus/map.jinja" import databus with context %}

{% set et   = databus.get('easytier', {}) %}
{% set img  = et.get('image', 'ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/easytier:v2.6.4') %}
{% set name = et.get('instance_name', 'nss-ndr-easytier') %}
{% set host = et.get('hostname', salt['grains.get']('host', 'nss-ai-agent')) %}

nss-ndr-easytier:
  docker_container.running:
    - name: nss-ndr-easytier
    - image: {{ img }}
    - restart_policy: unless-stopped
    # 见文件头说明：TUN 必须建在宿主 netns，故用 host 网络（不能同时挂 nss-net）
    - network_mode: host
    - detach: True
    - skip_translate: volumes
    - cap_add:
        - NET_ADMIN
        - NET_RAW
    - devices:
        - /dev/net/tun:/dev/net/tun
    - command:
        - --network-name
        - "{{ et.get('network_name', '') }}"
        - --network-secret
        - "{{ et.get('network_secret', '') }}"
        - --hostname
        - "{{ host }}"
        - --instance-name
        - "{{ name }}"
{%- if et.get('ipv4') %}
        # 固定虚拟 IP（不指定则下面的 -d 走 DHCP 自动分配）
        - --ipv4
        - "{{ et.ipv4 }}"
{%- else %}
        - --dhcp
{%- endif %}
{%- for p in et.get('peers', []) %}
        - --peers
        - "{{ p }}"
{%- endfor %}
{%- for e in et.get('external_nodes', []) %}
        - --external-node
        - "{{ e }}"
{%- endfor %}
{%- if et.get('relay_network_whitelist') is not none %}
        # 只为白名单内的网络转发流量（默认=本网络名；留空=不转发任何其他网络）
        - --relay-network-whitelist
        - "{{ et.get('relay_network_whitelist', et.get('network_name', '')) }}"
{%- endif %}
{%- if et.get('dev_name') %}
        - --dev-name
        - "{{ et.dev_name }}"
{%- endif %}
{%- if et.get('mtu') %}
        - --mtu
        - "{{ et.mtu }}"
{%- endif %}
{%- for n in et.get('proxy_networks', []) %}
        # ⚠ 子网代理：把本机可达网段暴露给虚拟网（如 172.16.196.0/24）
        - --proxy-networks
        - "{{ n }}"
{%- endfor %}
{%- for n in et.get('no_proxy_networks', []) %}
        - --no-proxy-networks
        - "{{ n }}"
{%- endfor %}
{%- if et.get('extra_args') %}
        - "{{ et.extra_args }}"
{%- endif %}
    - log_driver: json-file
    - require:
      - docker_image: {{ img }}
      - docker_network: ensure-nss-net-present
