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

# LLM Server 模型卷（只读挂到容器 /models）。
# 镜像 nss-ndr/llm-server 已内置 Qwen3-0.6B-Q8_0.gguf，正常情况无需外挂；
# 预留该卷用于以下场景：(1) 升级到更大模型；(2) 替换为非默认模型；(3) 多模型并存。
nss-ndr-llm-models:
  docker_volume.present
