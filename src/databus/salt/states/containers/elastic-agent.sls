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
    - name: /opt/nss-ndr/scripts/elastic-agent-start.sh
    - source: salt://databus/scripts/elastic-agent-start.sh
    - user: root
    - group: root
    - mode: "700"
    - makedirs: True

nss-ndr-elastic-agent:
  docker_container.running:
    - image: nss-ndr/elastic-agent-zeek:9.5.2
    - restart_policy: unless-stopped
    - user: root
    - binds:
        - nss-ndr-elastic-agent-data:/usr/share/elastic-agent/data
        - nss-ndr-elastic-agent-state:/usr/share/elastic-agent/state
        - nss-ndr-zeek-logs:/var/log/zeek:ro
        - /opt/nss-ndr/scripts/elastic-agent-start.sh:/opt/nss-ndr/scripts/elastic-agent-start.sh:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.elastic_agent }}
            - aliases:
                - elastic-agent
    - entrypoint: /opt/nss-ndr/scripts/elastic-agent-start.sh
    - environment:
        - TZ={{ databus.tz }}
        - FLEET_ENROLLMENT_TOKEN={{ env_get('ELASTIC_AGENT_ENROLLMENT_TOKEN') }}
        - FLEET_URL=https://fleet-server:8220
        - KIBANA_HOST=http://kibana:5601
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-elastic-agent-data
      - docker_volume: nss-ndr-elastic-agent-state
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: nss-ndr/elastic-agent-zeek:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
      - docker_container: nss-ndr-fleet-server
      - file: /opt/nss-ndr/scripts/elastic-agent-start.sh
