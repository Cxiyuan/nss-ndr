# ============================================================================
# Logstash 9.5.2（读 zeek-logs 卷 -> Redis Stream analysis:events）
# 自定义镜像 nss-ndr/logstash-databus
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs
  - databus.containers.elasticsearch
  - databus.containers.redis

{% from "databus/map.jinja" import databus with context %}

nss-ndr-logstash:
  docker_container.running:
    - image: nss-ndr/logstash-databus:9.5.2
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 保持镜像默认用户（logstash），与原始编排定义一致
    - binds:
        - nss-ndr-zeek-logs:/var/log/zeek:ro
        - nss-ndr-logstash-data:/usr/share/logstash/data
    - port_bindings:
        - "5044:5044"
        - "9600:9600"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.logstash }}
            - aliases:
                - logstash
    - environment:
        - TZ={{ databus.tz }}
        - REDIS_PASSWORD={{ databus.creds.redis_password }}
        - ES_PASSWORD={{ databus.creds.elastic_password }}
    - log_driver: json-file
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-logstash-data
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: nss-ndr/logstash-databus:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-redis
