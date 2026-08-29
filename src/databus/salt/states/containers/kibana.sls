# ============================================================================
# Kibana 9.5.2（Fleet 管理，service token 由 bootstrap 阶段写入 .env）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs
  - databus.containers.elasticsearch

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import env_get with context %}

nss-ndr-kibana:
  docker_container.running:
    - image: docker.elastic.co/kibana/kibana:9.5.2
    - restart_policy: unless-stopped
    # 保持镜像默认用户（kibana），与原始编排定义一致
    - binds:
        - nss-ndr-kibana-data:/usr/share/kibana/data
        - /etc/nss-ndr/kibana.yml:/usr/share/kibana/config/kibana.yml:ro
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.kibana }}:5601"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.kibana }}
            - aliases:
                - kibana
    - environment:
        - TZ={{ databus.tz }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - ELASTICSEARCH_SERVICEACCOUNTTOKEN={{ env_get('KIBANA_SERVICE_TOKEN') }}
        - KIBANA_SYSTEM_PASSWORD={{ databus.creds.elastic_password }}
        - XPACK_SECURITY_ENABLED=true
        - XPACK_ENCRYPTED_SAVED_OBJECTS=true
        - XPACK_ENCRYPTED_SAVED_OBJECTS_ENCRYPTIONKEY={{ databus.creds.kibana_encryption_key }}
        - XPACK_ENCRYPTED_SAVED_OBJECTS_ENCKEY={{ databus.creds.kibana_encryption_key }}
        - MONITORING_KIBANA_COLLECTION_ENABLED=true
        - XPACK_FLEET_ENABLED=true
        - XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["https://fleet-server:8220"]
        - FLEET_CA_TRUSTED_FINGERPRINT=
        - I18N_LOCALE=zh-CN
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "curl -fsS -u {{ databus.creds.elastic_username }}:{{ databus.creds.elastic_password }} http://localhost:5601/api/status | grep -q available"]
        - interval: 30000000000
        - timeout: 10000000000
        - retries: 20
        - start_period: 180000000000
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-kibana-data
      - docker_image: docker.elastic.co/kibana/kibana:9.5.2
      - docker_container: nss-ndr-elasticsearch
      - file: /etc/nss-ndr/kibana.yml
