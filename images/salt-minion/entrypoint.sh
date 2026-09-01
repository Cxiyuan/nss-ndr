#!/usr/bin/env sh
# ============================================================================
# nss-ndr salt-minion 容器入口
# ----------------------------------------------------------------------------
# 序列：
#   1) 渲染 /etc/salt-minion/minion（minion.tmpl → minion），替换 master/id
#   2) 前台启动 salt-minion
# 环境变量：
#   - SALT_MASTER_HOST             master host / IP（默认 salt-master-api）
#   - SALT_MINION_ID                minion id（默认主机 hostname）
#   - SALT_MINION_ROLES             逗号分隔 grains roles
# ============================================================================
set -eu

CFG_DIR="${SALT_CONFIG_DIR:-/etc/salt-minion}"
MINION_CFG="${CFG_DIR}/minion"

echo "[entrypoint] salt minion entrypoint starting..."

# ---------- 0) 装 pyzmq + docker-py（salt docker state 模块需要 docker-py 直连 docker daemon）----------
PIP_INDEX="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
python3 -c "import zmq, docker" 2>/dev/null \
  || pip3 install --no-cache-dir --break-system-packages -i "$PIP_INDEX" \
       pyzmq docker 2>&1 | tail -3

# ---------- 1) 渲染 minion 配置 ----------
mkdir -p "${CFG_DIR}" /etc/salt /var/run/salt /var/cache/salt /var/log/salt
if [ ! -f "${MINION_CFG}" ]; then
  cp "${CFG_DIR}/minion.tmpl" "${MINION_CFG}"
  # 替换 master host / minion id / roles
  sed -i "s|\${SALT_MASTER_HOST}|${SALT_MASTER_HOST:-salt-master-api}|" "${MINION_CFG}"
  sed -i "s|\${SALT_MINION_ID}|${SALT_MINION_ID:-$(hostname)}|" "${MINION_CFG}"
  echo "[entrypoint] minion config rendered: master=${SALT_MASTER_HOST:-salt-master-api} id=${SALT_MINION_ID:-$(hostname)}"
fi
ln -sf "${MINION_CFG}" /etc/salt/minion

# ---------- 2) 前台启动 salt-minion ----------
echo "[entrypoint] starting salt-minion (foreground)..."
exec salt-minion \
  --config-dir "${CFG_DIR}" \
  --pid-file /var/run/salt/minion.pid \
  >>/var/log/salt/minion 2>&1