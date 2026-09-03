# ============================================================================
# Salt Minion（nss-ndr/salt-minion）
# ----------------------------------------------------------------------------
# 容器以 nss-net + 特权运行（必须与本机 docker daemon 交互）：
#   - bind /var/run/docker.sock 让 docker state 模块能调用 docker CLI
#   - bind /srv/salt 与 /srv/pillar 与 master-api 共享（同一 nss-net 内 master 也 bind）
#   - bind /etc/nss-ndr 读写：bootstrap/fleet-setup 要写回 .env（动态 token），
#     configs.sls 要下发 kibana.yml 等配置；只读会导致这些 state 失败
# 注意：
#   - 容器必须有 docker.sock 写权限
#   - 必须先于 databus.containers.* 启动（minion 是 master 调度的执行者）
#   - 必须晚于 salt-master-api 启动（minion 要先 enroll 到 master）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.containers.salt-master-api

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import salt_minion with context %}
{% from "databus/map.jinja" import salt_master_api with context %}

nss-ndr-salt-minion:
  docker_container.running:
    - image: {{ salt_minion.image }}
    - restart_policy: unless-stopped
    # 与 master 同网段（nss-net），通过 alias salt-master-api 连接 master
    # network_mode 必须显式 nss-net（与线上容器一致；缺省会变 bridge 触发重建）
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    - networks:
        - nss-net:
            - ipv4_address: {{ salt_minion.ip }}
            - aliases:
                - salt-minion
    # 特权模式：让 salt-minion 能调用 docker CLI / cgroup
    - privileged: True
    - binds:
        # 顺序与线上容器 HostConfig.Binds 一致（docker_container 按序比较）
        - nss-ndr-salt-config-minion:/etc/salt-minion
        - nss-ndr-salt-run:/var/run/salt
        - nss-ndr-salt-cache:/var/cache/salt
        - nss-ndr-salt-log:/var/log/salt
        - /srv/salt:/srv/salt:ro
        - /srv/pillar:/srv/pillar:ro
        # /etc/nss-ndr 读写：bootstrap/fleet-setup 写回 .env，configs.sls 下发配置
        - /etc/nss-ndr:/etc/nss-ndr
        # Docker socket（Salt docker state 模块调用 dockerd）
        - /var/run/docker.sock:/var/run/docker.sock
    - environment:
        - TZ={{ databus.tz }}
        - SALT_MASTER_HOST=salt-master-api        # nss-net 内 alias（与 master 同网段）
        - SALT_MINION_ID={{ salt_minion.id }}
        - PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
        # Vault 只读凭据(kv: nss-ndr/*)供 vault-render-env.sh 派生 .env
        - VAULT_ADDR={{ databus.get('vault', {}).get('addr', 'http://vault:8200') }}
        - VAULT_TOKEN={{ databus.get('vault', {}).get('token', '') }}
    - log_driver: json-file
    - require:
      - docker_image: {{ salt_minion.image }}
      - docker_container: nss-ndr-salt-master-api
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-salt-config-minion
      - docker_volume: nss-ndr-salt-run
      - docker_volume: nss-ndr-salt-cache
      - docker_volume: nss-ndr-salt-log
