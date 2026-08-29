# ============================================================================
# Zeek 8.2.2（host 网络，监听 ens192，输出 JSON 到 zeek-logs 卷）
# 注意：network_mode host 下不能设置 hostname / 固定 IP
# 启动脚本 zeek-start.sh 由 Salt 下发并挂载进容器
# ============================================================================

include:
  - databus.volumes
  - databus.images

{% from "databus/map.jinja" import databus with context %}

deploy-zeek-start-script:
  file.managed:
    - name: /opt/nss-ndr/scripts/zeek-start.sh
    - source: salt://databus/scripts/zeek-start.sh
    - user: root
    - group: root
    - mode: "700"
    - makedirs: True

nss-ndr-zeek:
  docker_container.running:
    - image: nss-ndr/zeek:8.2.2
    - restart_policy: unless-stopped
    - network_mode: host
    # 保持镜像默认用户，与原始编排定义一致
    - cap_add:
        - NET_ADMIN
        - NET_RAW
        - SYS_ADMIN
    - devices:
        - /dev/net/tun:/dev/net/tun
    - binds:
        - nss-ndr-zeek-logs:/opt/zeek/logs
        - /opt/nss-ndr/scripts/zeek-start.sh:/opt/nss-ndr/scripts/zeek-start.sh:ro
    - entrypoint: /opt/nss-ndr/scripts/zeek-start.sh
    - environment:
        - TZ={{ databus.tz }}
        - ZEEK_INTERFACE={{ databus.zeek_interface }}
        - ZEEK_LOG_DIR=/opt/zeek/logs
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "ls /opt/zeek/logs/conn.log /opt/zeek/logs/current/conn.log 2>/dev/null | head -1"]
        - interval: 30000000000
        - timeout: 10000000000
        - retries: 5
        - start_period: 60000000000
    - require:
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: nss-ndr/zeek:8.2.2
      - file: /opt/nss-ndr/scripts/zeek-start.sh
