#!/usr/bin/env sh
# ============================================================================
# Vault 生命周期 bootstrap（server 启动 / init / unseal / kv seed）
# ----------------------------------------------------------------------------
# 设计要点：
#   - 无宿主机路径挂载：unseal key / root token 持久化到命名卷
#     nss-vault-secrets:/vault/secrets（容器数据卷,非宿主机 bind）
#   - 幂等：已 init 则跳过;unseal key 已保存则用其 unseal;已 seed 则跳过
#   - seed 密码来自容器 env（SEED_ELASTIC_PASSWORD / SEED_REDIS_PASSWORD /
#     SEED_KIBANA_ENCRYPTION_KEY）,由 salt state 从 pillar creds 渲染注入
#   - 本脚本作为容器 CMD：先启动 vault server（后台），完成 bootstrap 后
#     wait 保持前台（容器生命周期 = server 生命周期）
# 注意：
#   - 本脚本以 root 执行（Dockerfile 里 USER root,不 su-exec,
#     否则 vault server 由普通用户起后无法给文件设权限）
#   - disable_mlock=true（config 已设）→ 无需 IPC_LOCK cap
# ============================================================================
set -eu

VAULT_CONFIG="${VAULT_CONFIG_DIR:-/vault/config}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR
SECRETS_DIR="${VAULT_SECRETS_DIR:-/vault/secrets}"
INIT_FILE="${SECRETS_DIR}/vault-init.json"
UNSEAL_KEY_FILE="${SECRETS_DIR}/unseal_key"
RO_TOKEN_FILE="${SECRETS_DIR}/ro_token"
SEED_FLAG="${SECRETS_DIR}/.kv-seeded"

SEED_ELASTIC_PASSWORD="${SEED_ELASTIC_PASSWORD:-}"
SEED_REDIS_PASSWORD="${SEED_REDIS_PASSWORD:-}"
SEED_KIBANA_ENCRYPTION_KEY="${SEED_KIBANA_ENCRYPTION_KEY:-}"

log() { echo "[vault-bootstrap] $*"; }

# ---------- 1) 启动 vault server（后台） ----------
start_server() {
  if ! pgrep -f "vault server -config=${VAULT_CONFIG}" >/dev/null 2>&1; then
    log "启动 vault server -config=${VAULT_CONFIG}"
    # 需可写 /vault/file /vault/secrets（命名卷 mount，属主已由 Dockerfile entrypoint chown）
    mkdir -p /vault/file /vault/logs /vault/config /vault/secrets 2>/dev/null || true
    chown -R vault:vault /vault/file /vault/logs /vault/secrets 2>/dev/null || true
    # 当前若为 vault 用户直接跑;若为 root 则 su-exec 到 vault（避免 root 运行告警）
    if [ "$(id -u)" = "0" ]; then
      su-exec vault:vault vault server -config="${VAULT_CONFIG}" >/vault/logs/server.log 2>&1 &
    else
      vault server -config="${VAULT_CONFIG}" >/vault/logs/server.log 2>&1 &
    fi
    SERVER_PID=$!
  else
    log "vault server 已在运行"
  fi
}

wait_vault() {
  log "等待 vault server 就绪..."
  i=0
  until curl -fsS "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -gt 60 ]; then log "ERROR: vault 60s 内未就绪"; tail -20 /vault/logs/server.log 2>/dev/null || true; exit 1; fi
    sleep 1
  done
  log "vault server 就绪"
}

is_initialized() {
  curl -fsS "${VAULT_ADDR}/v1/sys/health" 2>/dev/null | grep -q '"initialized":true'
}
is_sealed() {
  curl -fsS "${VAULT_ADDR}/v1/sys/health" 2>/dev/null | grep -q '"sealed":true'
}

do_init() {
  log "首次 init（key-shares=1 key-threshold=1）..."
  mkdir -p "${SECRETS_DIR}"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT_FILE}"
  python3 - "${INIT_FILE}" "${UNSEAL_KEY_FILE}" <<'PYEOF'
import json, sys
init_file, key_file = sys.argv[1], sys.argv[2]
with open(init_file) as f:
    d = json.load(f)
with open(key_file, "w") as f:
    f.write(d["unseal_keys_b64"][0] + "\n")
# chmod 600
import os
os.chmod(key_file, 0o600)
print("root_token extracted to init file")
PYEOF
  log "init 完成: unseal key + root token 已保存到 ${SECRETS_DIR}"
}

do_unseal() {
  log "unsealing..."
  KEY=$(cat "${UNSEAL_KEY_FILE}")
  vault operator unseal "${KEY}" >/dev/null 2>&1
  log "unseal 完成"
}

create_ro_token() {
  log "创建 RO policy + token..."
  ROOT=$(python3 -c "import json; print(json.load(open('${INIT_FILE}'))['root_token'])")
  cat > /tmp/nss-ndr-ro.hcl <<'HCL'
path "nss-ndr/data/*" {
  capabilities = ["read"]
}
path "nss-ndr/metadata/*" {
  capabilities = ["read", "list"]
}
HCL
  VAULT_TOKEN="${ROOT}" vault policy write nss-ndr-ro /tmp/nss-ndr-ro.hcl >/dev/null
  TOKEN=$(VAULT_TOKEN="${ROOT}" vault token create -policy=nss-ndr-ro -ttl=87600h -field token)
  echo "${TOKEN}" > "${RO_TOKEN_FILE}"
  # RO token 是只读最小权限，供 salt-minion(vault-render-env) 等共享读取 → 644
  chmod 644 "${RO_TOKEN_FILE}"
  log "RO token 已创建并保存"
}

seed_kv() {
  log "seed kv: nss-ndr/{elastic,redis,kibana} ..."
  if [ -z "$SEED_ELASTIC_PASSWORD" ] || [ -z "$SEED_REDIS_PASSWORD" ] || [ -z "$SEED_KIBANA_ENCRYPTION_KEY" ]; then
    log "WARN: SEED_* env 为空,跳过 kv seed"
    return 0
  fi
  ROOT=$(python3 -c "import json; print(json.load(open('${INIT_FILE}'))['root_token'])")
  export VAULT_TOKEN="${ROOT}"
  vault kv put nss-ndr/elastic password="${SEED_ELASTIC_PASSWORD}" >/dev/null
  vault kv put nss-ndr/redis   password="${SEED_REDIS_PASSWORD}" >/dev/null
  vault kv put nss-ndr/kibana  encryption_key="${SEED_KIBANA_ENCRYPTION_KEY}" >/dev/null
  unset VAULT_TOKEN
  touch "${SEED_FLAG}"
  log "kv seed 完成"
}

# ---------- 主流程 ----------
start_server
wait_vault

if ! is_initialized; then
  do_init
fi
if is_sealed; then
  do_unseal
fi
if [ ! -f "${RO_TOKEN_FILE}" ]; then
  create_ro_token
fi
if [ ! -f "${SEED_FLAG}" ]; then
  seed_kv
fi

log "Vault bootstrap 完成,保持前台..."

# ---------- 保持前台（SERVER_PID 或 pgrep 到的 pid） ----------
if [ -n "${SERVER_PID:-}" ]; then
  wait "${SERVER_PID}"
else
  # 若无 SERVER_PID（重复启动场景）,tail -f server.log 保活
  tail -f /vault/logs/server.log
fi
