#!/usr/bin/env sh
# ============================================================================
# nss-ndr salt-master-api 容器入口
# ----------------------------------------------------------------------------
# 序列：
#   1) 渲染 /etc/salt-master-api/master 配置（master.tmpl → master）
#   2) 创建系统用户 saltapi（PAM external_auth）
#   3) 后台启动 salt-master，写日志到 /var/log/salt/master
#   4) 等 salt-master ZeroMQ 端口 4505 就绪
#   5) 前台启动 salt-api（salt 任务完成后 exec 即可）
# 环境变量：
#   - SALT_MASTER_INTERFACE         监听 IP（默认 0.0.0.0）
#   - SALT_API_USER                 salt-api 账号（默认 saltapi）
#   - SALT_API_PASSWORD             salt-api 密码（默认随机 24 位）
#   - SALT_API_PASSWORD_HASHED      若提供，优先使用 crypt(3) 哈希
#   - SALT_MASTER_ID                master id（默认 NSS-NDR-MASTER）
#   - SALT_API_PORT                 salt-api 端口（默认 8000）
# ============================================================================
set -eu

CFG_DIR="${SALT_CONFIG_DIR:-/etc/salt-master-api}"
MASTER_CFG="${CFG_DIR}/master"
API_CFG="${CFG_DIR}/api"

echo "[entrypoint] salt master+api entrypoint starting..."

# ---------- 1) 渲染 master 配置 ----------
mkdir -p "${CFG_DIR}" /etc/salt /var/run/salt /var/cache/salt /var/log/salt
if [ -f "${CFG_DIR}/master.tmpl" ] && [ ! -f "${MASTER_CFG}" ]; then
  cp "${CFG_DIR}/master.tmpl" "${MASTER_CFG}"
  sed -i "s/^interface:.*/interface: ${SALT_MASTER_INTERFACE:-0.0.0.0}/" "${MASTER_CFG}" || true
  sed -i "s/^  port: 8000/  port: ${SALT_API_PORT:-8000}/" "${MASTER_CFG}" || true
  echo "[entrypoint] master config rendered to ${MASTER_CFG}"
fi
ln -sf "${MASTER_CFG}" /etc/salt/master
[ -f "${API_CFG}" ] && ln -sf "${API_CFG}" /etc/salt/api

# ---------- 2) 创建/配置 saltapi 系统用户 ----------
SALT_API_USER="${SALT_API_USER:-saltapi}"
SALT_API_PASSWORD="${SALT_API_PASSWORD:-}"
SALT_API_PASSWORD_HASHED="${SALT_API_PASSWORD_HASHED:-}"

if ! id "${SALT_API_USER}" >/dev/null 2>&1; then
  adduser -D -H -s /sbin/nologin "${SALT_API_USER}"
  echo "[entrypoint] created user ${SALT_API_USER}"
fi
if [ -n "${SALT_API_PASSWORD_HASHED}" ]; then
  echo "${SALT_API_USER}:${SALT_API_PASSWORD_HASHED}" | chpasswd -e
elif [ -n "${SALT_API_PASSWORD}" ]; then
  echo "${SALT_API_USER}:${SALT_API_PASSWORD}" | chpasswd
fi

# ---------- 3) 后台启动 salt-master ----------
echo "[entrypoint] starting salt-master (background)..."
salt-master \
  --config-dir "${CFG_DIR}" \
  --pid-file /var/run/salt/salt-master.pid \
  >>/var/log/salt/master 2>&1 &
MASTER_PID=$!

# trap：容器退出时杀salt-master
trap "kill -TERM ${MASTER_PID} 2>/dev/null || true" EXIT INT TERM

# ---------- 4) 等 salt-master 端口 4505 就绪 ----------
i=0
while [ $i -lt 60 ]; do
  if (echo > /dev/tcp/127.0.0.1/4505) >/dev/null 2>&1; then
    echo "[entrypoint] salt-master 4505 ready"
    break
  fi
  i=$((i + 1))
  sleep 1
done

if ! (echo > /dev/tcp/127.0.0.1/4505) >/dev/null 2>&1; then
  echo "[entrypoint] ERROR: salt-master 4505 not ready after 60s" >&2
  tail -30 /var/log/salt/master >&2 || true
  exit 1
fi

# ---------- 5) 前台启动 salt-api ----------
echo "[entrypoint] starting salt-api (foreground)..."
exec salt-api \
  --config-dir "${CFG_DIR}" \
  --pid-file /var/run/salt/salt-api.pid \
  >>/var/log/salt/api 2>&1