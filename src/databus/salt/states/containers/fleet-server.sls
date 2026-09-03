# ============================================================================
# Fleet Server（elastic-agent 以 fleet-server 模式运行，8220）
# ----------------------------------------------------------------------------
# 采用 elastic-agent 原生 fleet-server 模式（FLEET_SERVER_ENABLE=true +
# FLEET_SERVER_SERVICE_TOKEN），与线上验证通过的容器定义一致：
#   - data 目录 /usr/share/fleet-server/data（卷）
#   - state 目录 /var/lib/fleet-server（卷，含 fleet.enc）
#   - elastic-agent.yml 烘焙进独立 fleet-server 镜像(默认 /etc/elastic-agent/elastic-agent.yml)
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.containers.elasticsearch
  - databus.containers.kibana

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import env_get with context %}

nss-ndr-fleet-server:
  docker_container.running:
    - image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/fleet-server:9.5.2
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 保持镜像默认用户 elastic-agent;fleet 配置已烘焙,仅数据/状态卷
    - binds:
        - nss-ndr-fleet-server-state:/var/lib/fleet-server
        - nss-ndr-fleet-server-data:/usr/share/fleet-server/data
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.fleet_server }}:8220"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.fleet_server }}
            - aliases:
                - fleet-server
    - environment:
        - TZ={{ databus.tz }}
        - FLEET_SERVER_ENABLE=true
        - FLEET_SERVER_ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - FLEET_SERVER_SERVICE_TOKEN={{ env_get('FLEET_SERVICE_TOKEN') }}
        - FLEET_SERVER_POLICY_ID=fleet-server-policy
    - log_driver: json-file
    - healthcheck:
        - test: ["CMD-SHELL", "elastic-agent status || exit 1"]
        - interval: 30000000000
        - timeout: 10000000000
        - retries: 3
        - start_period: 30000000000
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-fleet-server-data
      - docker_volume: nss-ndr-fleet-server-state
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/fleet-server:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
