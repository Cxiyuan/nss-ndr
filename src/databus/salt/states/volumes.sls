# ============================================================================
# 8 个命名数据卷（与原始编排定义一致）
# ============================================================================

nss-ndr-zeek-logs:
  docker_volume.present

nss-ndr-es-data:
  docker_volume.present

nss-ndr-es-backup:
  docker_volume.present

nss-ndr-kibana-data:
  docker_volume.present

nss-ndr-logstash-data:
  docker_volume.present

nss-ndr-elastic-agent-data:
  docker_volume.present

nss-ndr-redis-data:
  docker_volume.present

nss-ndr-fleet-server-data:
  docker_volume.present

# Fleet Server / Agent 的 state 目录（含 fleet.enc），挂卷后容器重建不丢 enroll 状态
nss-ndr-fleet-server-state:
  docker_volume.present

nss-ndr-elastic-agent-state:
  docker_volume.present
