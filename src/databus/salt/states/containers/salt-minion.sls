# ============================================================================
# Salt Minion（nss-ndr/salt-minion）
# ----------------------------------------------------------------------------
# 容器以 nss-net + 特权运行（必须与本机 docker daemon 交互）：
#   - bind /var/run/docker.sock 让 docker state 模块能调用 docker CLI
#   - bind /opt/nss/ndr 读写：统一配置根（file_roots/pillar_roots/.env/业务配置）
#     vault-seed/bootstrap/fleet-setup 写回 .env，configs.sls 下发业务配置
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
    # 整合镜像(salt:latest)无自带 ENTRYPOINT,此处显式指定 minion 入口
    - entrypoint: ["/sbin/tini", "--", "/usr/local/bin/salt-minion-entrypoint"]
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
        # 方案 C：统一配置根 /opt/nss/ndr 读写
        #   - file_roots/pillar_roots（salt 引擎目录）
        #   - .env（vault-seed/bootstrap/fleet-setup 写回动态 token）
        #   - 业务配置（configs.sls 下发到 /opt/nss/ndr/zeek 等,业务容器只读 bind）
        - /opt/nss/ndr:/opt/nss/ndr
        # Vault secrets 卷（RO token 由 vault bootstrap 写入;vault-render-env 从此读）
        - nss-vault-secrets:/vault/secrets:ro
        # Docker socket（Salt docker state 模块调用 dockerd）
        - /var/run/docker.sock:/var/run/docker.sock
    - environment:
        - TZ={{ databus.tz }}
        - SALT_MASTER_HOST=salt-master-api        # nss-net 内 alias（与 master 同网段）
        - SALT_MINION_ID={{ salt_minion.id }}
        - PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
        # Vault 地址（kv: nss-ndr/*）供 vault-render-env.sh 派生 .env
        # RO token 由 vault bootstrap 写入 nss-vault-secrets 卷,minion 只读共享该卷
        - VAULT_ADDR={{ databus.get('vault', {}).get('addr', 'http://vault:8200') }}
        - VAULT_SECRETS_DIR=/vault/secrets
    - log_driver: json-file
    - require:
      - docker_image: {{ salt_minion.image }}
      - docker_container: nss-ndr-salt-master-api
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-salt-config-minion
      - docker_volume: nss-ndr-salt-run
      - docker_volume: nss-ndr-salt-cache
      - docker_volume: nss-ndr-salt-log
      - docker_volume: nss-vault-secrets
