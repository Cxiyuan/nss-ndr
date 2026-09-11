# ============================================================================
# Redis 8.10.1（Stream 事件总线，自定义镜像 nss-ndr/redis-databus）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs

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
        # 方案 C：redis.conf 由 salt 下发宿主机 /opt/nss/ndr/redis, bind 进容器
        - /opt/nss/ndr/redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.redis }}:6379"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.redis }}
            - aliases:
                - redis
    - environment:
        - TZ={{ databus.tz }}
    # ⚠ 必须把配置文件作为 redis-server 的第一个参数传进去：
    #   原先只传 --requirepass/--maxmemory/--maxmemory-policy，没传配置文件 →
    #   bind / protected-mode / appendonly 等【全部不生效】。
    #   实测线上 appendonly=no（尽管 redis.conf 写的是 yes）—— Redis 实际
    #   根本没有持久化，容器一重建数据就丢（analyze-agent 的任务队列在内）。
    #   命令行参数优先于配置文件，两边的 maxmemory/maxmemory-policy 保持一致。
    - command:
        - redis-server
        - /usr/local/etc/redis/redis.conf
        - --requirepass
        - "{{ databus.creds.redis_password }}"
        - --maxmemory
        - 1gb
        - --maxmemory-policy
        - volatile-lru
    - log_driver: json-file
    - require:
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-redis-data
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/redis-databus:8.10.1
      - file: /opt/nss/ndr/redis/redis.conf
