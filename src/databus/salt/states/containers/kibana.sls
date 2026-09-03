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
    - image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/kibana:9.5.2
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # kibana.yml 已烘焙进镜像 /usr/share/kibana/config/kibana.yml
    # 保持镜像默认用户（kibana），与原始编排定义一致
    - binds:
        - nss-ndr-kibana-data:/usr/share/kibana/data
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
        # 加密 key 由 Vault 派生(.env),不再依赖 kibana.yml 硬编码默认值
        - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY={{ env_get('KIBANA_ENCRYPTION_KEY') }}
    - log_driver: json-file
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-kibana-data
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/kibana:9.5.2
      - docker_container: nss-ndr-elasticsearch
