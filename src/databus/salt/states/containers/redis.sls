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
    - image: nss-ndr/redis-databus:8.10.1
    - restart_policy: unless-stopped
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
        - REDIS_PASSWORD={{ databus.creds.redis_password }}
    - command: /bin/bash -lc "exec redis-server /usr/local/etc/redis/redis.conf --requirepass '{{ databus.creds.redis_password }}' --appendonly yes --appendfsync everysec --maxmemory 1gb --maxmemory-policy allkeys-lru"
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD", "redis-cli", "-a", "{{ databus.creds.redis_password }}", "--no-auth-warning", "ping"]
        - interval: 15000000000
        - timeout: 5000000000
        - retries: 10
        - start_period: 30000000000
    - require:
      - cmd: ensure-nss-network
      - docker_volume: nss-ndr-redis-data
      - docker_image: nss-ndr/redis-databus:8.10.1
