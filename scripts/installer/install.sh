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
PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"

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
# 优先使用 run 载荷 packages/ 中的离线安装包（docker / compose / salt 及依赖）
install_offline() {
  if [[ -d "${PAYLOAD_DIR}/packages" ]] && compgen -G "${PAYLOAD_DIR}/packages/*.rpm" >/dev/null; then
    local PM="dnf"
    command -v dnf >/dev/null 2>&1 || PM="yum"
    local TOTAL N
    TOTAL="$(ls "${PAYLOAD_DIR}"/packages/*.rpm | wc -l | tr -d ' ')"

    # 过滤：跳过目标系统已安装的同名包，避免离线包中的基础包版本与系统冲突
    # （离线包在构建机上生成，可能包含 rpm-libs/iptables-libs 等基础包的不同版本）
    local INSTALLED FILTERED
    INSTALLED="$(rpm -qa --queryformat '%{NAME}\n' 2>/dev/null || true)"
    FILTERED="$(mktemp /tmp/nss-ndr-offline.filtered.XXXXXX)"
    local rpm name
    for rpm in "${PAYLOAD_DIR}"/packages/*.rpm; do
      name="$(rpm -qp --queryformat '%{NAME}' "${rpm}" 2>/dev/null || true)"
      if [[ -n "${name}" ]] && ! grep -qxF "${name}" <<<"${INSTALLED}"; then
        echo "${rpm}" >> "${FILTERED}"
      fi
    done
    mapfile -t RPMS < "${FILTERED}"
    N="${#RPMS[@]}"

    say "检测到离线安装包（${TOTAL} 个 RPM，过滤后 ${N} 个需要安装）..."
    if [[ ${N} -eq 0 ]]; then
      say "所需组件均已安装，跳过离线安装"
      return 0
    fi

    if timeout 900 "$PM" install -y --nogpgcheck --disablerepo='*' "${RPMS[@]}" >/tmp/nss-ndr-offline.log 2>&1; then
      say "离线安装完成：$(docker --version 2>/dev/null | head -1 || echo docker?) / $(salt-call --version 2>/dev/null | head -1 || echo salt?)"
    else
      warn "全离线安装失败，尝试用系统源补充依赖（日志 /tmp/nss-ndr-offline.log）..."
      if timeout 900 "$PM" install -y --nogpgcheck "${RPMS[@]}" >>/tmp/nss-ndr-offline.log 2>&1; then
        say "离线包 + 系统源补充安装完成"
      else
        warn "离线包安装未完成，将尝试在线安装（日志 /tmp/nss-ndr-offline.log）"
        tail -n 15 /tmp/nss-ndr-offline.log >&2 2>/dev/null || true
      fi
    fi
    rm -f "${FILTERED}" 2>/dev/null || true
  fi
}
install_offline

install_docker() {
  say "未检测到 docker，开始安装 docker-ce..."
  local ok=0 PM="" LOG="/tmp/nss-ndr-docker-install.log"
  local REPO_BASE="" REPOMD="" FL=""

  if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PM="dnf"
    command -v dnf >/dev/null 2>&1 || PM="yum"

    # 直接写入 docker-ce 源（显式 EL_MAJOR，避免 $releasever 解析异常）
    cat > /etc/yum.repos.d/docker-ce.repo <<EOF
[docker-ce-stable]
name=Docker CE Stable - \$basearch
baseurl=https://download.docker.com/linux/centos/${EL_MAJOR}/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/centos/gpg
EOF

    # 预检仓库元数据：filelists 可用才走软件源安装，否则直接转 RPM 下载
    REPO_BASE="https://download.docker.com/linux/centos/${EL_MAJOR}/x86_64/stable"
    REPOMD="$(curl -fsSL -m 15 "${REPO_BASE}/repodata/repomd.xml" 2>/dev/null)" || REPOMD=""
    FL="$(printf '%s' "${REPOMD}" | grep -o 'repodata/[a-f0-9]\{32,\}-filelists\.xml\.gz' | head -1 || true)"
    if [[ -n "${FL}" ]] && curl -fsSI -m 15 "${REPO_BASE}/${FL}" >/dev/null 2>&1; then
      : > "${LOG}"
      # 依次尝试：普通安装 → --allowerasing → --nobest
      if timeout 90 "$PM" install -y docker-ce docker-ce-cli containerd.io >>"${LOG}" 2>&1; then
        ok=1
      elif timeout 90 "$PM" install -y --allowerasing docker-ce docker-ce-cli containerd.io >>"${LOG}" 2>&1; then
        ok=1
      elif timeout 90 "$PM" install -y --nobest docker-ce docker-ce-cli containerd.io >>"${LOG}" 2>&1; then
        ok=1
      fi
    else
      warn "docker-ce 软件源元数据不可用（${REPO_BASE}），跳过软件源安装，直接下载 RPM 包"
    fi
  fi

  # 方式二：直接下载官方/阿里云 RPM 安装（绕开仓库元数据损坏/网络不稳）
  if [[ ${ok} -ne 1 ]] && [[ -n "${PM}" ]]; then
    warn "改为直接下载 docker RPM 包安装..."
    local BASE="" LIST="" DOCKER_CE="" DOCKER_CLI="" CONTAINERD="" RPM_DIR=""
    RPM_DIR="$(mktemp -d /tmp/nss-ndr-docker-rpms.XXXXXX)"
    for try_base in \
        "https://download.docker.com/linux/centos/${EL_MAJOR}/x86_64/stable/Packages" \
        "https://mirrors.aliyun.com/docker-ce/linux/centos/${EL_MAJOR}/x86_64/stable/Packages" \
        "https://mirrors.cloud.tencent.com/docker-ce/linux/centos/${EL_MAJOR}/x86_64/stable/Packages"; do
      BASE="${try_base}"
      LIST="$(curl -fsSL -m 20 "${BASE}/" 2>>"${LOG}")" || LIST=""
      DOCKER_CE="$(printf '%s' "${LIST}" | grep -o 'href="docker-ce-[0-9][^"]*\.rpm"' | sed 's/href="//;s/"//' | sort -V | tail -1 || true)"
      DOCKER_CLI="$(printf '%s' "${LIST}" | grep -o 'href="docker-ce-cli-[0-9][^"]*\.rpm"' | sed 's/href="//;s/"//' | sort -V | tail -1 || true)"
      CONTAINERD="$(printf '%s' "${LIST}" | grep -o 'href="containerd.io-[0-9][^"]*\.rpm"' | sed 's/href="//;s/"//' | sort -V | tail -1 || true)"
      [[ -n "${DOCKER_CE}" && -n "${DOCKER_CLI}" && -n "${CONTAINERD}" ]] && break
    done

    if [[ -n "${DOCKER_CE}" && -n "${DOCKER_CLI}" && -n "${CONTAINERD}" ]]; then
      say "下载 RPM：${DOCKER_CE} / ${DOCKER_CLI} / ${CONTAINERD}"
      if curl -fsSL -m 60 -o "${RPM_DIR}/docker-ce.rpm" "${BASE}/${DOCKER_CE}" >>"${LOG}" 2>&1 \
         && curl -fsSL -m 60 -o "${RPM_DIR}/docker-ce-cli.rpm" "${BASE}/${DOCKER_CLI}" >>"${LOG}" 2>&1 \
         && curl -fsSL -m 60 -o "${RPM_DIR}/containerd.io.rpm" "${BASE}/${CONTAINERD}" >>"${LOG}" 2>&1 \
         && [[ -s "${RPM_DIR}/docker-ce.rpm" && -s "${RPM_DIR}/docker-ce-cli.rpm" && -s "${RPM_DIR}/containerd.io.rpm" ]]; then
        say "安装 RPM（首次可能需下载依赖元数据，耗时几分钟）..."
        RPM_OPTS=(--disablerepo=docker-ce-stable)
        # 先用已缓存的仓库元数据快速安装，失败再允许刷新元数据
        if timeout 120 "$PM" install -y --cacheonly "${RPM_OPTS[@]}" \
              "${RPM_DIR}/docker-ce.rpm" "${RPM_DIR}/docker-ce-cli.rpm" "${RPM_DIR}/containerd.io.rpm" >>"${LOG}" 2>&1; then
          ok=1
        elif timeout 600 "$PM" install -y "${RPM_OPTS[@]}" \
              "${RPM_DIR}/docker-ce.rpm" "${RPM_DIR}/docker-ce-cli.rpm" "${RPM_DIR}/containerd.io.rpm" >>"${LOG}" 2>&1; then
          ok=1
        fi
        if [[ ${ok} -eq 1 ]]; then
          # 仓库元数据损坏会拖慢后续 dnf 操作，安装成功后禁用该源
          sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
        fi
      fi
    else
      warn "未能从官方/阿里云仓库获取 docker RPM 列表"
    fi
  fi

  # 方式三：get.docker.com 官方脚本兜底
  if [[ ${ok} -ne 1 ]]; then
    warn "RPM 安装未成功，最后尝试 get.docker.com 官方脚本..."
    if curl -fsSL https://get.docker.com | sh >>"${LOG}" 2>&1; then
      ok=1
    fi
  fi

  if [[ ${ok} -ne 1 ]]; then
    err "docker 安装失败（详细日志：${LOG}），请检查网络/软件源后手动安装 docker 并重新执行本安装包"
    tail -n 25 "${LOG}" >&2 2>/dev/null || true
    return 1
  fi

  systemctl enable --now docker >/dev/null 2>&1 || true
  say "docker 安装完成：$(docker --version 2>/dev/null || echo OK)"
}

command -v docker >/dev/null 2>&1 || install_docker
systemctl start docker >/dev/null 2>&1 || true
docker version >/dev/null 2>&1 || { err "docker 安装后仍不可用，请检查网络与软件源"; exit 1; }
say "docker 就绪：$(docker --version)"

install_compose() {
  say "未检测到 docker compose，安装 v2 插件..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  if curl -fsSL -m 60 "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose; then
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  else
    warn "GitHub 下载 compose 失败，尝试 docker-ce 仓库安装 docker-compose-plugin RPM..."
    rm -f /usr/local/lib/docker/cli-plugins/docker-compose
    local PM="dnf" BASE="" LIST="" COMPOSE_PLUGIN=""
    command -v dnf >/dev/null 2>&1 || PM="yum"
    BASE="https://mirrors.aliyun.com/docker-ce/linux/centos/${EL_MAJOR}/x86_64/stable/Packages"
    LIST="$(curl -fsSL -m 20 "${BASE}/" 2>/dev/null)" || LIST=""
    COMPOSE_PLUGIN="$(printf '%s' "${LIST}" | grep -o 'href="docker-compose-plugin-[0-9][^"]*\.rpm"' | sed 's/href="//;s/"//' | sort -V | tail -1 || true)"
    if [[ -n "${COMPOSE_PLUGIN}" ]] && timeout 180 "$PM" install -y --disablerepo=docker-ce-stable \
        "${BASE}/${COMPOSE_PLUGIN}" >/dev/null 2>&1; then
      say "docker-compose-plugin 安装完成"
    else
      warn "compose 插件安装未完成，可稍后手动安装 docker compose"
    fi
  fi
}

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  install_compose
fi
say "docker compose 就绪：$(docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo N/A)"

install_salt() {
  say "未检测到 salt，开始安装 salt-minion（SaltStack 官方源，EL${EL_MAJOR}）..."
  rpm --import "https://repo.saltproject.io/salt/py3/redhat/${EL_MAJOR}/x86_64/latest/SALTSTACK-GPG-KEY.pub" || true
  if ! curl -fsSL -m 60 "https://repo.saltproject.io/salt/py3/redhat/${EL_MAJOR}/x86_64/latest/salt.repo" \
      -o /etc/yum.repos.d/salt.repo; then
    warn "salt.repo 下载失败，salt-minion 可能安装不上（后续可手动安装）"
  fi
  if ! (timeout 300 dnf install -y salt-minion 2>/dev/null || timeout 300 yum install -y salt-minion); then
    warn "salt-minion 安装失败，请稍后手动安装后继续部署"
  fi
  systemctl enable salt-minion >/dev/null 2>&1 || true
}

command -v salt-call >/dev/null 2>&1 || install_salt
say "salt 就绪：$(salt-call --version 2>/dev/null | head -1 || echo N/A)"

# ---------- 3. 安装目录与载荷 ----------
say "安装目录：${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"/{images,logs,config}

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
    docker load -i "${t}" || { err "镜像导入失败：$(basename "${t}")"; exit 1; }
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
  docker images --format '    {{.Repository}}:{{.Tag}} ({{.Size}})' | grep -E 'nss-ndr|elasticsearch|kibana' | sort -u || true
echo
echo "  部署配置   : ${INSTALL_DIR}/config/deploy.conf"
echo "  Salt 状态  : /srv/salt/databus/ + /srv/salt/agent/"
echo "  Pillar     : /srv/pillar/databus.sls + /srv/pillar/agent.sls（按需改密码/模型配置）"
echo "  下一步     : 配置 /etc/nss-ndr/.env 与 pillar 后执行："
echo "              salt-call --local state.apply databus.deploy"
echo "              salt-call --local state.apply agent.deploy"
echo "============================================================"
