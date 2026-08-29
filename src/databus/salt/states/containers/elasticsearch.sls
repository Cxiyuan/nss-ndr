# ============================================================================
# Elasticsearch 9.5.2（security enabled，basic license，单节点）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images

{% from "databus/map.jinja" import databus with context %}

nss-ndr-elasticsearch:
  docker_container.running:
    - image: docker.elastic.co/elasticsearch/elasticsearch:9.5.2
    - restart_policy: unless-stopped
    # 注意：ES 禁止以 root 运行，必须使用镜像默认用户（elasticsearch/uid 1000）
    - environment:
        - discovery.type=single-node
        - xpack.security.enabled=true
        - xpack.security.http.ssl.enabled=false
        - xpack.security.transport.ssl.enabled=false
        - xpack.license.self_generated.type=basic
        - xpack.ml.enabled=false
        - ELASTIC_PASSWORD={{ databus.creds.elastic_password }}
        - ES_JAVA_OPTS=-Xms2g -Xmx4g
        - cluster.routing.allocation.disk.threshold_enabled=true
        - cluster.routing.allocation.disk.watermark.low=85%
        - cluster.routing.allocation.disk.watermark.high=90%
        - action.destructive_requires_name=false
        - indices.query.bool.max_clause_count=4096
    - ulimits:
        - memlock=-1:-1
        - nofile=65536:65536
    - binds:
        - nss-ndr-es-data:/usr/share/elasticsearch/data
        - nss-ndr-es-backup:/usr/share/elasticsearch/backup
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.es }}:9200"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.elasticsearch }}
            - aliases:
                - elasticsearch
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "curl -fsS -u {{ databus.creds.elastic_username }}:{{ databus.creds.elastic_password }} http://localhost:9200/_cluster/health | grep -qE 'green|yellow'"]
        - interval: 30000000000
        - timeout: 15000000000
        - retries: 20
        - start_period: 120000000000
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-es-data
      - docker_volume: nss-ndr-es-backup
      - docker_image: docker.elastic.co/elasticsearch/elasticsearch:9.5.2
