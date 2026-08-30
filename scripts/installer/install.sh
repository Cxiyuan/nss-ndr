#!/usr/bin/env bash
# ============================================================
# nss-ndr 深瞳安全分析智能体 · 部署安装脚本
# 目标平台：Linux Anolis OS（x86_64）
#
# 功能：
#   1) 检测 docker / docker compose / salt，缺失则自动安装
#   2) 安装目录（默认 /opt/nss-agent）
#   3) 检测服务器网卡，列出清单供选择"流量镜像/监控网卡"
#   4) 关闭并禁止 firewalld 自启
#   5) 导入全部容器镜像（docker load）
#   6) 安装 Salt 状态到 /srv/salt（agent + databus）与 pillar
#
# 用法：sudo ./nss-ndr-installer-<版本>.run [安装目录]
# ============================================================
set -euo pipefail

INSTALL_DIR="${1:-/opt/nss-agent}"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }

usage() {
  echo "用法: sudo ./$0 [安装目录]"
  echo "  [安装目录] 默认 /opt/nss-agent"
  echo "环境变量: NSS_NIC=网卡名 可跳过网卡交互选择"
}

[[ $# -gt 1 ]] && { usage; exit 1; }
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

[[ ${EUID} -eq 0 ]] || { err "请使用 root 或 sudo 执行本安装包"; exit 1; }

echo
echo "============================================================"
echo "  nss-ndr 深瞳安全分析智能体 · 部署安装包"
echo "  目标平台：Linux Anolis OS / x86_64"
echo "============================================================"
echo

# ---------- 1. 系统与架构检测 ----------
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi
OS_ID="${ID:-unknown}"
OS_VER="${VERSION_ID:-unknown}"
say "系统：${PRETTY_NAME:-${OS_ID} ${OS_VER}}"

case "${OS_ID}" in
  anolis|openanolis|centos|rhel|rocky|almalinux|tencentos|openeuler|kylin)
    ;;
  *)
    warn "当前系统（${OS_ID}）不是 Anolis OS，安装继续尝试，如遇兼容问题请反馈"
    ;;
esac

EL_MAJOR=8
[[ "${OS_VER}" =~ ^(9|23) ]] && EL_MAJOR=9

[[ "$(uname -m)" == "x86_64" ]] || { err "仅支持 x86_64 架构"; exit 1; }

# ---------- 2. docker / compose / salt 检测与安装 ----------
install_docker() {
  say "未检测到 docker，开始安装 docker-ce..."
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y yum-utils
    yum-config-manager --add-repo "https://download.docker.com/linux/centos/${EL_MAJOR}/docker-ce.repo" >/dev/null 2>&1 || true
    dnf install -y docker-ce docker-ce-cli containerd.io
  elif command -v yum >/dev/null 2>&1; then
    yum install -y yum-utils
    yum-config-manager --add-repo "https://download.docker.com/linux/centos/${EL_MAJOR}/docker-ce.repo" >/dev/null 2>&1 || true
    yum install -y docker-ce docker-ce-cli containerd.io
  else
    warn "未找到 dnf/yum，改用 get.docker.com 官方脚本安装"
    curl -fsSL https://get.docker.com | sh
  fi
  systemctl enable --now docker
}

command -v docker >/dev/null 2>&1 || install_docker
systemctl start docker >/dev/null 2>&1 || true
docker version >/dev/null 2>&1 || { err "docker 安装后仍不可用，请检查网络与软件源"; exit 1; }
say "docker 就绪：$(docker --version)"

install_compose() {
  say "未检测到 docker compose，安装 v2 插件..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
}

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  install_compose
fi
say "docker compose 就绪：$(docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo N/A)"

install_salt() {
  say "未检测到 salt，开始安装 salt-minion（SaltStack 官方源，EL${EL_MAJOR}）..."
  rpm --import "https://repo.saltproject.io/salt/py3/redhat/${EL_MAJOR}/x86_64/latest/SALTSTACK-GPG-KEY.pub" || true
  curl -fsSL "https://repo.saltproject.io/salt/py3/redhat/${EL_MAJOR}/x86_64/latest/salt.repo" \
    -o /etc/yum.repos.d/salt.repo
  dnf install -y salt-minion 2>/dev/null || yum install -y salt-minion
  systemctl enable salt-minion >/dev/null 2>&1 || true
}

command -v salt-call >/dev/null 2>&1 || install_salt
say "salt 就绪：$(salt-call --version 2>/dev/null | head -1 || echo N/A)"

# ---------- 3. 安装目录与载荷 ----------
say "安装目录：${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"/{images,logs,config}

PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -d "${PAYLOAD_DIR}/images" ]] && compgen -G "${PAYLOAD_DIR}/images/*.tar" >/dev/null; then
  say "拷贝镜像包到 ${INSTALL_DIR}/images/ ..."
  cp -f "${PAYLOAD_DIR}"/images/*.tar "${INSTALL_DIR}/images/"
else
  warn "载荷中未发现镜像包（安装包可能被裁剪），跳过拷贝"
fi

# ---------- 4. 安装 Salt 状态（masterless fileserver 布局） ----------
if [[ -d "${PAYLOAD_DIR}/salt/agent" ]] && [[ -d "${PAYLOAD_DIR}/salt/databus" ]]; then
  say "安装 Salt 状态到 /srv/salt ..."

  # databus：states 顶层拍平到 /srv/salt/databus/，子目录与 files/scripts 跟随
  mkdir -p /srv/salt/databus /srv/salt/agent /srv/pillar
  (
    cd "${PAYLOAD_DIR}/salt/databus/states"
    cp -f ./*.sls ./*.jinja /srv/salt/databus/ 2>/dev/null || true
    cp -rf containers teardown /srv/salt/databus/ 2>/dev/null || true
  )
  cp -rf "${PAYLOAD_DIR}"/salt/databus/files "${PAYLOAD_DIR}"/salt/databus/scripts /srv/salt/databus/
  cp -f "${PAYLOAD_DIR}/salt/databus/pillar.example" /srv/pillar/databus.sls

  # agent：states/* + files/ + scripts/ 平铺到 /srv/salt/agent/
  (
    cd "${PAYLOAD_DIR}/salt/agent"
    cp -rf states/* files scripts /srv/salt/agent/ 2>/dev/null || true
  )
  cp -f "${PAYLOAD_DIR}/salt/agent/pillar.example" /srv/pillar/agent.sls

  # pillar top.sls（不存在时生成；已存在则提示手动补充）
  if [[ ! -f /srv/pillar/top.sls ]]; then
    cat > /srv/pillar/top.sls <<'EOF'
base:
  '*':
    - databus
    - agent
EOF
    say "已生成 /srv/pillar/top.sls（base: * -> databus, agent）"
  else
    warn "/srv/pillar/top.sls 已存在，请确认包含 databus / agent 两个 pillar"
  fi
else
  warn "载荷中未发现 Salt 状态，跳过 /srv/salt 安装"
fi

# ---------- 5. 网卡检测与选择（流量镜像 / 监控网卡） ----------
echo
say "检测服务器网卡（已过滤 lo/docker/veth/br 等虚拟接口）"
mapfile -t NICS < <(ls /sys/class/net | grep -Ev '^(lo|lo0|docker0|veth.*|br-.*|virbr.*|tun.*|tap.*|bond.*)')

if [[ ${#NICS[@]} -eq 0 ]]; then
  err "未检测到可用物理网卡"; exit 1
fi

for i in "${!NICS[@]}"; do
  nic="${NICS[$i]}"
  ip4="$(ip -o -4 addr show "${nic}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
  mac="$(cat "/sys/class/net/${nic}/address" 2>/dev/null)"
  state="$(cat "/sys/class/net/${nic}/operstate" 2>/dev/null)"
  printf '  [%2d] %-14s state=%-7s ip=%-16s mac=%s\n' \
    "$((i+1))" "${nic}" "${state:-unknown}" "${ip4:--}" "${mac:--}"
done

if [[ -n "${NSS_NIC:-}" ]]; then
  MONITOR_NIC="${NSS_NIC}"
  say "使用环境变量指定网卡：${MONITOR_NIC}"
elif [[ -t 0 ]]; then
  while :; do
    read -r -p "请输入要用于流量镜像/监控的网卡编号 [1]: " sel
    sel="${sel:-1}"
    if [[ "${sel}" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#NICS[@]} )); then
      MONITOR_NIC="${NICS[$((sel-1))]}"
      break
    fi
    warn "输入无效，请输入 1-${#NICS[@]}"
  done
else
  MONITOR_NIC="${NICS[0]}"
  warn "非交互模式，默认选用第一块网卡：${MONITOR_NIC}"
fi
say "已选择监控网卡：${MONITOR_NIC}"

# ---------- 5. 关闭并禁止 firewalld ----------
say "关闭并禁止 firewalld 自启..."
systemctl disable --now firewalld >/dev/null 2>&1 || true
if systemctl is-active firewalld >/dev/null 2>&1; then
  warn "firewalld 仍处于活动状态，请手动检查"
else
  say "firewalld 已停止并禁止开机自启"
fi

# ---------- 6. 导入镜像 ----------
if compgen -G "${INSTALL_DIR}/images/*.tar" >/dev/null; then
  say "导入容器镜像（共 $(ls "${INSTALL_DIR}"/images/*.tar | wc -l | tr -d ' ') 个，可能耗时较长）..."
  for t in "${INSTALL_DIR}"/images/*.tar; do
    say "docker load $(basename "${t}")"
    docker load -i "${t}"
  done
else
  warn "无镜像包可导入"
fi

# ---------- 7. 生成部署配置 ----------
cat > "${INSTALL_DIR}/config/deploy.conf" <<EOF
# nss-ndr 部署配置（由安装包生成，$(date '+%F %T')）
INSTALL_DIR=${INSTALL_DIR}
MONITOR_NIC=${MONITOR_NIC}
ZEEK_INTERFACE=${MONITOR_NIC}
OS_ID=${OS_ID}
OS_VERSION=${OS_VER}
DOCKER_VERSION=$(docker --version 2>/dev/null || echo N/A)
COMPOSE_VERSION=$(docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo N/A)
SALT_VERSION=$(salt-call --version 2>/dev/null | head -1 || echo N/A)
EOF

echo
echo "============================================================"
say "部署环境安装完成 ✓"
echo "  安装目录   : ${INSTALL_DIR}"
echo "  监控网卡   : ${MONITOR_NIC}"
echo "  已导入镜像 :"
docker images --format '    {{.Repository}}:{{.Tag}} ({{.Size}})' | grep -E 'nss-ndr|elasticsearch|kibana' | sort -u
echo
echo "  部署配置   : ${INSTALL_DIR}/config/deploy.conf"
echo "  Salt 状态  : /srv/salt/databus/ + /srv/salt/agent/"
echo "  Pillar     : /srv/pillar/databus.sls + /srv/pillar/agent.sls（按需改密码/模型配置）"
echo "  下一步     : 配置 /etc/nss-ndr/.env 与 pillar 后执行："
echo "              salt-call --local state.apply databus.deploy"
echo "              salt-call --local state.apply agent.deploy"
echo "============================================================"
