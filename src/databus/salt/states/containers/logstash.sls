# ============================================================================
# Logstash 9.5.2（读 zeek-logs 卷 -> Redis Stream analysis:events）
# 自定义镜像 nss-ndr/logstash-databus，jvm.options 外挂
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
    # 保持镜像默认用户（logstash），与原始编排定义一致
    - binds:
        - nss-ndr-logstash-data:/usr/share/logstash/data
        - nss-ndr-zeek-logs:/var/log/zeek:ro
        - /etc/nss-ndr/jvm.options:/usr/share/logstash/config/jvm.options:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.logstash }}
            - aliases:
                - logstash
    - environment:
        - TZ={{ databus.tz }}
        - LS_JAVA_OPTS=-Xms1g -Xmx2g
        - MONITORING_ENABLED=false
        - ELASTIC_USERNAME={{ databus.creds.elastic_username }}
        - ELASTIC_PASSWORD={{ databus.creds.elastic_password }}
        - REDIS_PASSWORD={{ databus.creds.redis_password }}
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "curl -fsS http://localhost:9600/_node/stats >/dev/null"]
        - interval: 30000000000
        - timeout: 10000000000
        - retries: 10
        - start_period: 120000000000
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-logstash-data
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: nss-ndr/logstash-databus:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-redis
      - file: /etc/nss-ndr/jvm.options
