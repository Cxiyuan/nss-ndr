# ============================================================================
# Vault 容器（nss-vault，凭据管理：应用密码唯一来源）
# ----------------------------------------------------------------------------
# 设计（2026-09-09 方案 C 重构）：
#   - vault.hcl 由 configs.sls 下发宿主机 /opt/nss/ndr/vault/vault.hcl, bind 只读
#   - vault-bootstrap.sh bake 镜像（程序）；init/unseal/kv-seed 幂等
#   - unseal key / root token / RO token 存命名卷 nss-vault-secrets
#   - seed 密码来自 pillar creds（SEED_* env 注入，仅首次 seed 用）
#   - kv 一旦 seed 完成（/.kv-seeded 标记），改 pillar creds 不再覆盖 vault
#     （vault 是唯一真源；改密码应改 vault kv 而不是 pillar）
# 上下游：
#   - 必须先于 salt-minion 的 vault-render-env（vault-seed.sls）执行
#     （vault-seed 从 vault 读密码写 /opt/nss/ndr/.env）
#   - 必须先于所有依赖凭据的容器（es/redis/kibana...）
#   - vault.hcl 需先由 configs.sls 下发（require databus.configs）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs

{% from "databus/map.jinja" import databus with context %}

# 容器固定 IP（nss-net 内，alias vault 供其他容器访问）
{% set vault_ip = databus.fixed_ips.get('vault', '192.168.250.10') %}
{% set vault_img = 'ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/vault:latest' %}

nss-vault:
  docker_container.running:
    - name: nss-vault
    - image: {{ vault_img }}
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    - binds:
        - nss-vault-data:/vault/file
        - nss-vault-logs:/vault/logs
        - nss-vault-secrets:/vault/secrets
        # 方案 C：vault.hcl 由 salt 下发宿主机 /opt/nss/ndr/vault, bind 进容器
        - /opt/nss/ndr/vault/vault.hcl:/vault/config/vault.hcl:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ vault_ip }}
            - aliases:
                - vault
    - environment:
        - TZ={{ databus.tz }}
        - VAULT_ADDR=http://127.0.0.1:8200
        - VAULT_CONFIG_DIR=/vault/config
        - VAULT_SECRETS_DIR=/vault/secrets
        # seed 密码（仅首次 init+seed 用；seed 后改 vault kv 才生效）
        - SEED_ELASTIC_PASSWORD={{ databus.creds.elastic_password }}
        - SEED_REDIS_PASSWORD={{ databus.creds.redis_password }}
        - SEED_KIBANA_ENCRYPTION_KEY={{ databus.creds.kibana_encryption_key }}
    - log_driver: json-file
    - require:
      - docker_image: {{ vault_img }}
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-vault-data
      - docker_volume: nss-vault-logs
      - docker_volume: nss-vault-secrets
      - file: /opt/nss/ndr/vault/vault.hcl
