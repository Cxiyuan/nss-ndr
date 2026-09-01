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
    - image: nss-ndr/elasticsearch:9.5.2
    - restart_policy: unless-stopped
    # network_mode 必须显式 nss-net（与线上容器一致）；detach/skip_translate 消除 docker-py 对比伪差异
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 注意：ES 禁止以 root 运行，必须使用镜像默认用户（elasticsearch/uid 1000）
    - environment:
        - TZ={{ databus.tz }}
        - discovery.type=single-node
        - xpack.security.enabled=true
        - xpack.security.http.ssl.enabled=false
        - xpack.security.transport.ssl.enabled=false
        - xpack.license.self_generated.type=basic
        - xpack.ml.enabled=false
        - ELASTIC_PASSWORD={{ databus.creds.elastic_password }}
        - ES_JAVA_OPTS=-Xms2g -Xmx4g
        - action.destructive_requires_name=false
        - indices.query.bool.max_clause_count=4096
    - ulimits:
        - memlock=-1:-1
        - nofile=65536:65536
    - binds:
        - nss-ndr-es-backup:/usr/share/elasticsearch/backup
        - nss-ndr-es-data:/usr/share/elasticsearch/data
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.es }}:9200"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.elasticsearch }}
            - aliases:
                - elasticsearch
    - log_driver: json-file
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-es-data
      - docker_volume: nss-ndr-es-backup
      - docker_image: nss-ndr/elasticsearch:9.5.2
