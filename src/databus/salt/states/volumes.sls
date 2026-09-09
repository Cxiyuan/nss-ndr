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
# 镜像 nss-ndr/llm-server 已内置 Qwen3.8-2B-Q4_K_M.gguf，正常情况无需外挂；
# 预留该卷用于以下场景：(1) 升级到更大模型；(2) 替换为非默认模型；(3) 多模型并存。
nss-ndr-llm-models:
  docker_volume.present

# Salt Master + API 容器持久化卷（pki / log / cache / run）
nss-ndr-salt-config:
  docker_volume.present
nss-ndr-salt-run:
  docker_volume.present
nss-ndr-salt-cache:
  docker_volume.present
nss-ndr-salt-log:
  docker_volume.present

# Salt Minion 容器配置卷（与 master 共享 run/cache/log）
nss-ndr-salt-config-minion:
  docker_volume.present

# Vault 容器卷（2026-09-08 重构：vault 纳入 salt 管理,无宿主机挂载）
# nss-vault-data:  file backend 持久化(kv 数据)
# nss-vault-logs:  vault server 日志
# nss-vault-secrets: init/unseal key/root token/RO token（非宿主机路径）
nss-vault-data:
  docker_volume.present

nss-vault-logs:
  docker_volume.present

nss-vault-secrets:
  docker_volume.present
