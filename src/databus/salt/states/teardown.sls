# ============================================================================
# 数据总线一键清理（只清理本项目，不影响 zabbix/grafana/postgres 等业务）
# ----------------------------------------------------------------------------
# 清理范围：nss-ndr-* 容器 + nss-net + nss-ndr-* 卷
# 保留范围：镜像 tar / 镜像 / /opt/nss-ndr 配置（便于快速重装）
# 如需同时删除镜像：跑 salt-call --local state.apply databus.teardown.images
# ============================================================================

# ---- 容器 ----
nss-ndr-zeek:
  docker_container.absent:
    - force: True

nss-ndr-elasticsearch:
  docker_container.absent:
    - force: True

nss-ndr-kibana:
  docker_container.absent:
    - force: True

nss-ndr-fleet-server:
  docker_container.absent:
    - force: True

nss-ndr-elastic-agent:
  docker_container.absent:
    - force: True

nss-ndr-logstash:
  docker_container.absent:
    - force: True

nss-ndr-redis:
  docker_container.absent:
    - force: True

nss-ndr-llm-server:
  docker_container.absent:
    - force: True

# ---- 网络（容器删除后）----
nss-net:
  docker_network.absent:
    - require:
      - docker_container: nss-ndr-zeek
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
      - docker_container: nss-ndr-fleet-server
      - docker_container: nss-ndr-elastic-agent
      - docker_container: nss-ndr-logstash
      - docker_container: nss-ndr-redis
      - docker_container: nss-ndr-llm-server
      - docker_container: nss-ndr-salt-master-api
      - docker_container: nss-ndr-salt-minion
      - docker_container: nss-vault

# ---- 数据卷（网络删除后）----
nss-ndr-zeek-logs:
  docker_volume.absent:
    - force: True

nss-ndr-es-data:
  docker_volume.absent:
    - force: True

nss-ndr-es-backup:
  docker_volume.absent:
    - force: True

nss-ndr-kibana-data:
  docker_volume.absent:
    - force: True

nss-ndr-logstash-data:
  docker_volume.absent:
    - force: True

nss-ndr-elastic-agent-data:
  docker_volume.absent:
    - force: True

nss-ndr-redis-data:
  docker_volume.absent:
    - force: True

nss-ndr-fleet-server-data:
  docker_volume.absent:
    - force: True

# ---- Salt 控制面容器 + 卷（master/minion 由编排 deploy 重建）----
nss-ndr-salt-master-api:
  docker_container.absent:
    - force: True

nss-ndr-salt-minion:
  docker_container.absent:
    - force: True

# ---- Vault 容器（凭据管理；vault kv 数据在 nss-vault-data 卷）----
nss-vault:
  docker_container.absent:
    - force: True

# ---- Salt / Vault 卷 ----
nss-ndr-salt-config:
  docker_volume.absent:
    - force: True

nss-ndr-salt-run:
  docker_volume.absent:
    - force: True

nss-ndr-salt-cache:
  docker_volume.absent:
    - force: True

nss-ndr-salt-log:
  docker_volume.absent:
    - force: True

nss-ndr-salt-config-minion:
  docker_volume.absent:
    - force: True

nss-vault-data:
  docker_volume.absent:
    - force: True

nss-vault-logs:
  docker_volume.absent:
    - force: True

nss-vault-secrets:
  docker_volume.absent:
    - force: True
