#!/usr/bin/env sh
# ============================================================================
# Vault 生命周期 bootstrap（server 启动 / init / unseal / kv seed）
# ----------------------------------------------------------------------------
# 依赖：仅用镜像自带 wget + vault CLI + busybox sh
#   （官方 vault 镜像无 curl/python3，故探测用 wget、解析用 grep/sed）
# 设计要点：
#   - unseal key / root token / RO token 持久化到命名卷 nss-vault-secrets
#   - 幂等：已 init 跳过；unseal key 已存则 used；已 seed 跳过
#   - seed 密码来自容器 env（SEED_*，由 salt state 从 pillar creds 渲染注入）
#   - 本脚本作为容器 CMD：先启动 vault server（后台），bootstrap 后 wait 保活
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

# vault server 启动过程中 /v1/sys/health 在 sealed 状态返回 501（不支持），
# 改用 /v1/sys/init（unsealed/initialized server 总可访问）作就绪探测
health() { wget -q -O- "${VAULT_ADDR}/v1/sys/init" >/dev/null 2>&1; }

# ---------- 1) 启动 vault server（后台） ----------
start_server() {
  if ! pgrep -f "vault server -config=${VAULT_CONFIG}" >/dev/null 2>&1; then
    log "启动 vault server -config=${VAULT_CONFIG}"
    mkdir -p /vault/file /vault/logs /vault/config /vault/secrets 2>/dev/null || true
    chown -R vault:vault /vault/file /vault/logs /vault/secrets 2>/dev/null || true
    if [ "$(id -u)" = "0" ]; then
      su-exec vault:vault vault server -config="${VAULT_CONFIG}" >/vault/logs/server.log 2>&1 &
    else
      vault server -config="${VAULT_CONFIG}" >/vault/logs/server.log 2>&1 &
    fi
    # 脚本主流程能看到的全局变量（不能 local，否则函数返回后丢失）
    SERVER_PID=$!
    export SERVER_PID
  else
    log "vault server 已在运行"
  fi
}

wait_vault() {
  log "等待 vault server 就绪..."
  i=0
  until health >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -gt 90 ]; then
      log "ERROR: vault 90s 内未就绪"
      tail -20 /vault/logs/server.log 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
  log "vault server 就绪"
}

# is_initialized/is_sealed 走 /v1/sys/init（health 在 sealed 状态下 501 不工作）
is_initialized() { wget -q -O- "${VAULT_ADDR}/v1/sys/init" 2>/dev/null | grep -q '"initialized":true'; }
is_sealed()      { wget -q -O- "${VAULT_ADDR}/v1/sys/init" 2>/dev/null | grep -q '"sealed":true'; }

do_init() {
  log "首次 init（key-shares=1 key-threshold=1）..."
  mkdir -p "${SECRETS_DIR}"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT_FILE}"
  # 提取 unseal key（优先 unseal_keys_b64，兼容 keys_base64）
  grep -o '"unseal_keys_b64":\["[^"]*"' "${INIT_FILE}" | sed 's/.*\["//; s/"$//' > "${UNSEAL_KEY_FILE}" || true
  if [ ! -s "${UNSEAL_KEY_FILE}" ]; then
    grep -o '"keys_base64":\["[^"]*"' "${INIT_FILE}" | sed 's/.*\["//; s/"$//' > "${UNSEAL_KEY_FILE}" || true
  fi
  if [ ! -s "${UNSEAL_KEY_FILE}" ]; then
    log "ERROR: 无法从 init 输出提取 unseal key"; cat "${INIT_FILE}"; exit 1
  fi
  chmod 600 "${UNSEAL_KEY_FILE}"
  log "init 完成: unseal key + root token 已保存到 ${SECRETS_DIR}"
}

root_token() { grep -o '"root_token":"[^"]*"' "${INIT_FILE}" | sed 's/.*":"//; s/"$//'; }

do_unseal() {
  log "unsealing..."
  KEY=$(cat "${UNSEAL_KEY_FILE}")
  vault operator unseal "${KEY}" >/dev/null 2>&1
  log "unseal 完成"
}

create_ro_token() {
  log "创建 RO policy + token..."
  ROOT=$(root_token)
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
  chmod 644 "${RO_TOKEN_FILE}"
  log "RO token 已创建并保存"
}

seed_kv() {
  log "seed kv: nss-ndr/{elastic,redis,kibana} ..."
  if [ -z "$SEED_ELASTIC_PASSWORD" ] || [ -z "$SEED_REDIS_PASSWORD" ] || [ -z "$SEED_KIBANA_ENCRYPTION_KEY" ]; then
    log "WARN: SEED_* env 为空,跳过 kv seed"
    return 0
  fi
  ROOT=$(root_token)
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/elastic password="${SEED_ELASTIC_PASSWORD}" >/dev/null
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/redis   password="${SEED_REDIS_PASSWORD}" >/dev/null
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/kibana  encryption_key="${SEED_KIBANA_ENCRYPTION_KEY}" >/dev/null
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

# vault server 是 su-exec 子 shell 启动的（孙进程），wait 无参会立即返回
# 导致脚本退出 + 容器反复重启。改用 tail -f server.log 保活（alpine busybox 有）
exec tail -F /vault/logs/server.log
