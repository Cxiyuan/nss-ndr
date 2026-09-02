# ============================================================================
# Redis 8.10.1（Stream 事件总线，自定义镜像 nss-ndr/redis-databus）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images

{% from "databus/map.jinja" import databus with context %}

nss-ndr-redis:
  docker_container.running:
    - image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/redis-databus:8.10.1
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 保持镜像默认用户，与原始编排定义一致
    - binds:
        - nss-ndr-redis-data:/data
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.redis }}:6379"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.redis }}
            - aliases:
                - redis
    - environment:
        - TZ={{ databus.tz }}
    - command: ["redis-server", "--requirepass", "{{ databus.creds.redis_password }}", "--maxmemory", "1gb", "--maxmemory-policy", "allkeys-lru"]
    - log_driver: json-file
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-redis-data
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/redis-databus:8.10.1
