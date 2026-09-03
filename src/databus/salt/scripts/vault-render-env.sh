#!/usr/bin/env bash
# ============================================================================
# 从 Vault 派生 /etc/nss-ndr/.env 的基础凭据(kv-v2: nss-ndr/elastic|redis|kibana)
# ----------------------------------------------------------------------------
# 幂等合并:只覆写 ELASTIC_PASSWORD / REDIS_PASSWORD / KIBANA_ENCRYPTION_KEY 三键,
# 其余键(动态 token 等)原样保留;文件不存在则新建(600)。
# 由 salt 编排 deploy-vault-seed 在 salt-minion 容器内执行(需要 VAULT_TOKEN 环境变量,
# 经 salt-minion 容器 env 注入)。
# ============================================================================
set -euo pipefail

ENV_FILE="${NSS_ENV_FILE:-/etc/nss-ndr/.env}"
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

if [[ -z "$VAULT_TOKEN" ]]; then
  echo "[vault-render-env] ERROR: VAULT_TOKEN 未设置" >&2
  exit 1
fi

fetch_kv() { # $1=secret path  $2=data key
  curl -fsS -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/nss-ndr/data/${1}" |
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['${2}'])"
}

EP=$(fetch_kv elastic password)
RP=$(fetch_kv redis password)
KE=$(fetch_kv kibana encryption_key)

python3 - "${ENV_FILE}" "${EP}" "${RP}" "${KE}" <<'PYEOF'
import os, sys
path, ep, rp, ke = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines = []
if os.path.exists(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    if not lines:
        lines = []

def setkv(key, val):
    for i, l in enumerate(lines):
        if l.startswith(key + "="):
            lines[i] = f"{key}={val}"
            return
    lines.append(f"{key}={val}")

setkv("ELASTIC_PASSWORD", ep)
setkv("REDIS_PASSWORD", rp)
setkv("KIBANA_ENCRYPTION_KEY", ke)
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
print("[vault-render-env] .env 基础凭据已由 Vault 派生")
PYEOF
