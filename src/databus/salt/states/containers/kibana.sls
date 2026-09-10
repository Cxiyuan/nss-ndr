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
    # kibana.yml 由 salt 下发宿主机 /opt/nss/ndr/kibana, bind 进容器覆盖镜像默认
    # 保持镜像默认用户（kibana），与原始编排定义一致
    - binds:
        - nss-ndr-kibana-data:/usr/share/kibana/data
        - /opt/nss/ndr/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:ro
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
      - file: /opt/nss/ndr/kibana/kibana.yml
    # kibana.yml 变更必须重启才生效（docker_container.running 不会因为
    # bind 文件内容变化而重启容器）
    - watch:
      - file: /opt/nss/ndr/kibana/kibana.yml
