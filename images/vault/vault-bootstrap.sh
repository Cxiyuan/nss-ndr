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

stop_server() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  pkill -f "vault server -config=${VAULT_CONFIG}" 2>/dev/null || true
  i=0
  while pgrep -f "vault server -config=${VAULT_CONFIG}" >/dev/null 2>&1 && [ "$i" -lt 30 ]; do
    i=$((i+1)); sleep 1
  done
  SERVER_PID=""
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

# is_initialized/is_sealed 用 vault status -format=json
# （/v1/sys/init 只返回 {"initialized":bool}，无 sealed 字段；
#  /v1/sys/health 在 sealed 下 503 且 wget 不输出 body）
# set -e 注意：vault status 在 sealed 时 exit 2，但管道退出码取 grep（末位命令），不会触发 errexit
is_initialized() { vault status -format=json 2>/dev/null | grep -q '"initialized": *true'; }
is_sealed()      { vault status -format=json 2>/dev/null | grep -q '"sealed": *true'; }

do_init() {
  log "init（key-shares=1 key-threshold=1，可能已存在 init）..."
  mkdir -p "${SECRETS_DIR}"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT_FILE}"
  # unseal key 提取：优先 unseal_keys_b64（hashicorp vault 2.x），兼容 keys_base64（1.x）
  # 注意 init json 是格式化多行，必须先 tr -d '\n' 压成单行（awk/grep 都逐行处理）
  unseal_b64=$(json_val unseal_keys_b64)
  if [ -z "$unseal_b64" ]; then
    unseal_b64=$(json_val keys_base64)
  fi
  if [ -z "$unseal_b64" ]; then
    log "ERROR: 无法提取 unseal key"; head -20 "${INIT_FILE}"; exit 1
  fi
  printf '%s\n' "$unseal_b64" > "${UNSEAL_KEY_FILE}"
  chmod 600 "${UNSEAL_KEY_FILE}"
  log "init 完成: unseal key + root token 已保存到 ${SECRETS_DIR}"
}

# 从 init json 提取字段值（json 多行格式化，先 tr -d '\n' 压成单行再按 '"' 切字段）
# 匹配字段名 k 后第一个长度 >=20 的值（避开 ": [" 之类的语法字段；
# unseal key 44 字符 / root token 24 字符，均 >=20）
json_val() {
  tr -d '\n' < "${INIT_FILE}" | awk -F'"' -v k="$1" '
    { for (i=1; i<=NF; i++) if ($i == k) { for (j=i+1; j<=NF; j++) if (length($j) >= 20) { print $j; exit } } }'
}

root_token() { json_val root_token; }

do_unseal() {
  log "unsealing..."
  KEY=$(cat "${UNSEAL_KEY_FILE}")
  vault operator unseal "${KEY}" >/dev/null 2>&1 || { log "ERROR: unseal 失败"; return 1; }
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
  VAULT_TOKEN="${ROOT}" vault policy write nss-ndr-ro /tmp/nss-ndr-ro.hcl >/dev/null || return 1
  TOKEN=$(VAULT_TOKEN="${ROOT}" vault token create -policy=nss-ndr-ro -ttl=87600h -field token 2>/dev/null || true)
  if ! token_valid "${TOKEN}"; then
    log "ERROR: RO token 生成失败"
    return 1
  fi
  printf '%s\n' "${TOKEN}" > "${RO_TOKEN_FILE}"
  chmod 644 "${RO_TOKEN_FILE}"
  log "RO token 已创建并保存"
}

# token 看起来有效（hvs.xxx，长度 >=20）
token_valid() {
  [ -n "${1:-}" ] || return 1
  [ "${#1}" -ge 20 ]
}

# 启用 KV v2 于 nss-ndr/（幂等；seed/RO policy 依赖此挂载）
ensure_kv_mount() {
  ROOT=$(root_token)
  if VAULT_TOKEN="${ROOT}" vault secrets list -format=json 2>/dev/null | grep -q '"nss-ndr/"'; then
    log "KV v2 已挂载: nss-ndr/"
  else
    log "启用 KV v2: nss-ndr/"
    VAULT_TOKEN="${ROOT}" vault secrets enable -path=nss-ndr kv-v2 >/dev/null 2>&1 \
      || { log "ERROR: 启用 KV 失败"; return 1; }
  fi
}

# 调高 token auth 后端 max_lease_ttl（默认 768h=32d，否则 10 年 RO token 会被截断为 32d）
tune_token_ttl() {
  ROOT=$(root_token)
  VAULT_TOKEN="${ROOT}" vault write sys/auth/token/tune max_lease_ttl=87600h >/dev/null 2>&1 \
    || { log "WARN: 调整 token max_lease_ttl 失败"; return 1; }
  log "token max_lease_ttl 已设为 87600h"
}

seed_kv() {
  log "seed kv: nss-ndr/{elastic,redis,kibana} ..."
  if [ -z "$SEED_ELASTIC_PASSWORD" ] || [ -z "$SEED_REDIS_PASSWORD" ] || [ -z "$SEED_KIBANA_ENCRYPTION_KEY" ]; then
    log "WARN: SEED_* env 为空,跳过 kv seed"
    return 0
  fi
  ROOT=$(root_token)
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/elastic password="${SEED_ELASTIC_PASSWORD}" >/dev/null || return 1
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/redis   password="${SEED_REDIS_PASSWORD}" >/dev/null || return 1
  VAULT_TOKEN="${ROOT}" vault kv put nss-ndr/kibana  encryption_key="${SEED_KIBANA_ENCRYPTION_KEY}" >/dev/null || return 1
  touch "${SEED_FLAG}"
  log "kv seed 完成"
}

# ---------- 主流程 ----------
start_server
wait_vault

# 状态判断（幂等 + 自愈，绝不删有效 unseal key）：
if [ -s "${UNSEAL_KEY_FILE}" ]; then
  # A) secrets 有非空 unseal key
  if ! is_initialized; then
    # data 卷被清但 secrets 还在（陈旧）→ 丢弃陈旧 secrets，重新 init
    log "secrets 有 unseal key 但 server 未 init（data 卷被清），重新 init"
    rm -f "${INIT_FILE}" "${UNSEAL_KEY_FILE}" "${RO_TOKEN_FILE}" "${SEED_FLAG}" 2>/dev/null || true
    do_init
  fi
  # 否则（server 已 init）直接用现有 key unseal（正常重启路径，绝不删 key）
elif is_initialized; then
  # B) 无可用 unseal key 但 server 已 init：data 卷有状态却无法 unseal
  #    （secrets 卷被清或早期脚本缺陷）→ 停 server、清 data 卷、重启后重新 init
  log "server 已 init 但 unseal key 不可用，清空 data 卷后重新 init"
  stop_server
  rm -rf /vault/file/* 2>/dev/null || true
  rm -f "${INIT_FILE}" "${RO_TOKEN_FILE}" "${SEED_FLAG}" 2>/dev/null || true
  start_server
  wait_vault
  do_init
else
  # C) 全新部署
  do_init
fi

# unseal（sealed 且有 key）
if is_sealed && [ -s "${UNSEAL_KEY_FILE}" ]; then
  do_unseal || log "WARN: unseal 失败（下次重启重试）"
fi

# 确保 KV v2 挂载（seed/RO policy 依赖）
if ! is_sealed; then
  ensure_kv_mount || log "WARN: KV v2 挂载失败"
  tune_token_ttl || true
fi

# RO token：文件缺失或内容无效则重建
if ! token_valid "$(cat "${RO_TOKEN_FILE}" 2>/dev/null)"; then
  create_ro_token || log "WARN: 创建 RO token 失败（vault 可能 sealed,后续重试）"
fi
if [ ! -f "${SEED_FLAG}" ]; then
  seed_kv || log "WARN: kv seed 失败（vault 可能 sealed,后续重试）"
fi

log "Vault bootstrap 完成,保持前台..."

# vault server 是 su-exec 子 shell 启动的（孙进程），wait 无参会立即返回
# 导致脚本退出 + 容器反复重启。改用 tail -f server.log 保活（alpine busybox 有）
exec tail -F /vault/logs/server.log
