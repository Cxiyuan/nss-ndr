# ============================================================================
# Elastic Agent（Fleet-managed，应用 Zeek Integration policy）
# 读取 /var/log/zeek（zeek-logs 卷），enroll 到 fleet-server
# 启动脚本 elastic-agent-start.sh 由 Salt 下发并挂载进容器：
#   首次启动无 fleet.enc -> enroll 到 fleet-server；之后 run 应用 policy
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.containers.elasticsearch
  - databus.containers.kibana
  - databus.containers.fleet-server

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import env_get with context %}

deploy-elastic-agent-start-script:
  file.managed:
    - name: /srv/salt/databus/scripts/elastic-agent-start.sh
    - source: salt://databus/scripts/elastic-agent-start.sh
    - user: root
    - group: root
    - mode: "644"
    - makedirs: True

nss-ndr-elastic-agent:
  docker_container.running:
    - image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/elastic-agent-zeek:9.5.2
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 与线上验证通过的容器一致：镜像默认用户 elastic-agent + privileged
    - privileged: True
    - binds:
        - nss-ndr-elastic-agent-data:/usr/share/elastic-agent/data
        - nss-ndr-elastic-agent-state:/var/lib/elastic-agent
        - nss-ndr-zeek-logs:/var/log/zeek:ro
        - /srv/salt/databus/scripts/elastic-agent-start.sh:/opt/nss-ndr/scripts/elastic-agent-start.sh:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.elastic_agent }}
            - aliases:
                - elastic-agent
    - command: /opt/nss-ndr/scripts/elastic-agent-start.sh
    - environment:
        - TZ={{ databus.tz }}
        - FLEET_URL=https://fleet-server:8220
        - FLEET_ENROLLMENT_TOKEN={{ env_get('ELASTIC_AGENT_ENROLLMENT_TOKEN') }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    - log_driver: json-file
    - healthcheck:
        - test: ["CMD-SHELL", "elastic-agent status || exit 1"]
        - interval: 30000000000
        - timeout: 10000000000
        - retries: 3
        - start_period: 30000000000
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-elastic-agent-data
      - docker_volume: nss-ndr-elastic-agent-state
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/elastic-agent-zeek:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
      - docker_container: nss-ndr-fleet-server
      - file: /srv/salt/databus/scripts/elastic-agent-start.sh
