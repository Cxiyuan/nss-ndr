# ============================================================================
# Salt Minion（nss-ndr/salt-minion）
# ----------------------------------------------------------------------------
# 容器以 host network + 特权运行（必须与本机 docker daemon / cgroup 交互）：
#   - bind /var/run/docker.sock 让 docker state 模块能调用 docker CLI
#   - bind /srv/salt 与 /srv/pillar 与 master-api 共享（同一 nss-net 内 master 也 bind）
#   - bind /etc/nss-ndr 读取 .env（动态 token）
# 注意：
#   - 容器必须有 docker.sock 写权限
#   - 必须先于 databus.containers.* 启动（minion 是 master 调度的执行者）
#   - 必须晚于 salt-master-api 启动（minion 要先 enroll 到 master）
# ============================================================================

include:
  - databus.network
  - databus.images
  - databus.containers.salt-master-api

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import salt_minion with context %}
{% from "databus/map.jinja" import salt_master_api with context %}

nss-ndr-salt-minion:
  docker_container.running:
    - image: {{ salt_minion.image }}
    - restart_policy: unless-stopped
    # 必须 host network（Salt ZeroMQ 4505/4506 通信）
    - network_mode: host
    # 特权模式：让 salt-minion 能调用 docker CLI / cgroup
    - privileged: True
    - binds:
        # Docker socket（Salt docker state 模块调用 dockerd）
        - /var/run/docker.sock:/var/run/docker.sock
        # 与 master-api 共享 state 文件
        - nss-ndr-salt-config-minion:/etc/salt-minion
        - nss-ndr-salt-run:/var/run/salt
        - nss-ndr-salt-cache:/var/cache/salt
        - nss-ndr-salt-log:/var/log/salt
        - /srv/salt:/srv/salt:rw
        - /srv/pillar:/srv/pillar:rw
        # 读取 .env（dynamic token）
        - /etc/nss-ndr:/etc/nss-ndr:ro
    - environment:
        - TZ={{ databus.tz }}
        - SALT_MASTER_HOST={{ salt_master_api.ip }}        # nss-net 内 alias
        - SALT_MINION_ID={{ salt_minion.id }}
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        # minion 与 master 建立 ZeroMQ 连接后 8000 端口才能正常返回 jobs
        - test: ["CMD-SHELL", "salt-call --config-dir /etc/salt-minion test.ping 2>&1 | grep -q True || (echo > /dev/tcp/127.0.0.1/4505) >/dev/null 2>&1"]
        - interval: 60000000000
        - timeout: 10000000000
        - retries: 10
        - start_period: 90000000000
    - require:
      - docker_image: {{ salt_minion.image }}
      - docker_container: nss-ndr-salt-master-api
      - docker_volume: nss-ndr-salt-config-minion
      - docker_volume: nss-ndr-salt-run
      - docker_volume: nss-ndr-salt-cache
      - docker_volume: nss-ndr-salt-log