# ============================================================================
# Fleet Server（elastic-agent 以 fleet-server 模式运行，8220）
# 启动脚本 fleet-server-start.sh 由 Salt 下发并挂载进容器：
#   首次启动无 fleet.enc -> enroll 到 Kibana/ES；之后以 fleet-server 模式运行
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs
  - databus.containers.elasticsearch
  - databus.containers.kibana

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import env_get with context %}

deploy-fleet-server-start-script:
  file.managed:
    - name: /opt/nss-ndr/scripts/fleet-server-start.sh
    - source: salt://databus/scripts/fleet-server-start.sh
    - user: root
    - group: root
    - mode: "700"
    - makedirs: True

nss-ndr-fleet-server:
  docker_container.running:
    - image: nss-ndr/elastic-agent-zeek:9.5.2
    - restart_policy: unless-stopped
    - user: root
    - binds:
        - nss-ndr-fleet-server-data:/usr/share/elastic-agent/data
        - nss-ndr-fleet-server-state:/usr/share/elastic-agent/state
        - /etc/nss-ndr/elastic-agent-fleet-server.yml:/usr/share/elastic-agent/elastic-agent.yml:ro
        - /opt/nss-ndr/scripts/fleet-server-start.sh:/opt/nss-ndr/scripts/fleet-server-start.sh:ro
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.fleet_server }}:8220"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.fleet_server }}
            - aliases:
                - fleet-server
    - entrypoint: /opt/nss-ndr/scripts/fleet-server-start.sh
    - environment:
        - TZ={{ databus.tz }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - ELASTICSEARCH_USERNAME={{ databus.creds.elastic_username }}
        - ELASTICSEARCH_PASSWORD={{ databus.creds.elastic_password }}
        - KIBANA_HOST=http://kibana:5601
        - FLEET_URL=https://fleet-server:8220
        - FLEET_ENROLLMENT_TOKEN={{ env_get('FLEET_ENROLLMENT_TOKEN') }}
        - FLEET_SERVER_ENABLE=true
        - FLEET_SERVER_POLICY_NAME=nss-ndr-fleet-server-policy
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-fleet-server-data
      - docker_volume: nss-ndr-fleet-server-state
      - docker_image: nss-ndr/elastic-agent-zeek:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
      - file: /etc/nss-ndr/elastic-agent-fleet-server.yml
      - file: /opt/nss-ndr/scripts/fleet-server-start.sh
