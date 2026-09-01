#!/usr/bin/env sh
# ============================================================================
# nss-ndr salt-master-api 容器入口（Python 3.10 镜像版）
# ----------------------------------------------------------------------------
# 序列：
#   1) 装 pyzmq / cherrypy / tornado（Alpine musl wheel，首次启动需要）
#   2) 渲染 /etc/salt-master-api/master 配置（master.tmpl → master）
#   3) 后台启动 salt-master，写日志到 /var/log/salt/master
#   4) 等 salt-master ZeroMQ 端口 4505 就绪（用 nc -z）
#   5) 前台启动 salt-api
# 环境变量：
#   - SALT_MASTER_INTERFACE         监听 IP（默认 0.0.0.0）
#   - SALT_API_PORT                 salt-api 端口（默认 8000）
#   - PIP_INDEX_URL                 pip 源（默认清华镜像）
# ============================================================================
set -eu

CFG_DIR="${SALT_CONFIG_DIR:-/etc/salt-master-api}"
MASTER_CFG="${CFG_DIR}/master"
API_CFG="${CFG_DIR}/api"

echo "[entrypoint] salt master+api entrypoint starting..."

# ---------- 0) 装运行时依赖（salt 需要，Alpine musl wheel）----------
PIP_INDEX="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
python3 -c "import zmq, cherrypy, tornado" 2>/dev/null \
  || pip3 install --no-cache-dir --break-system-packages -i "$PIP_INDEX" \
       pyzmq cherrypy tornado 2>&1 | tail -3

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

# ---------- 2) 后台启动 salt-master ----------
echo "[entrypoint] starting salt-master (background)..."
salt-master \
  --config-dir "${CFG_DIR}" \
  --pid-file /var/run/salt/salt-master.pid \
  >>/var/log/salt/master 2>&1 &
MASTER_PID=$!

trap "kill -TERM ${MASTER_PID} 2>/dev/null || true" EXIT INT TERM

# ---------- 3) 等 salt-master 端口 4505 就绪 ----------
echo "[entrypoint] waiting salt-master 4505..."
i=0
while [ $i -lt 60 ]; do
  if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 4505)); s.close()" 2>/dev/null; then
    echo "[entrypoint] salt-master 4505 ready (after ${i}s)"
    break
  fi
  i=$((i + 1))
  sleep 1
done

if ! python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 4505)); s.close()" 2>/dev/null; then
  echo "[entrypoint] ERROR: salt-master 4505 not ready after 60s" >&2
  tail -30 /var/log/salt/master >&2 || true
  exit 1
fi

# ---------- 4) 前台启动 salt-api ----------
echo "[entrypoint] starting salt-api (foreground)..."
exec salt-api \
  --config-dir "${CFG_DIR}" \
  --pid-file /var/run/salt/salt-api.pid \
  >>/var/log/salt/api 2>&1