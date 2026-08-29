# ============================================================================
# 数据总线一键清理（只清理本项目，不影响 zabbix/grafana/postgres 等业务）
# ----------------------------------------------------------------------------
# 清理范围：nss-ndr-* 容器（7 个）+ nss-net + nss-ndr-* 卷（10 个）
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

nss-ndr-agent:
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
      - docker_container: nss-ndr-agent

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
