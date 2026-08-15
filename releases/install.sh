#!/usr/bin/env bash
# NSS-NDR 探针一键安装/部署脚本（幂等，可重复执行）
# 用法:
#   bash releases/install.sh -i enp5s0 [-c configs/probe.yaml] [-t <镜像tag>] [-p 30603] [--timeout <秒>] [--images <dir>]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/deploy/k3s"
NS="nss-ndr"

INTERFACE=""
CONFIG_FILE=""
TAG=""
MANAGER_PORT=30603
SKIP_CHECKS=0
TIMEOUT=1800
IMAGES_DIR=""

usage() {
  echo "用法: $0 [选项]"
  echo "  -i, --interface <网卡>   抓包网卡（必填，如 enp5s0/eth1）"
  echo "  -c, --config <文件>      probe 配置（默认 configs/probe.yaml，不存在则从示例复制）"
  echo "  -t, --tag <镜像tag>      覆盖镜像版本（默认用 kustomization 当前 pin）"
  echo "  -p, --manager-port <端口> 管理后台 NodePort（默认 30603）"
  echo "  --timeout <秒>            组件就绪等待超时（默认 1800，慢网络拉镜像可调大）"
  echo "  --images <dir>            本地离线镜像目录（默认 releases/images；存在则本地加载，不拉网络）"
  echo "  --skip-checks            跳过环境预检"
  echo "  -h, --help               显示帮助"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--interface) INTERFACE="$2"; shift 2 ;;
    -c|--config) CONFIG_FILE="$2"; shift 2 ;;
    -t|--tag) TAG="$2"; shift 2 ;;
    -p|--manager-port) MANAGER_PORT="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --images) IMAGES_DIR="$2"; shift 2 ;;
    --skip-checks) SKIP_CHECKS=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "未知参数: $1"; usage 1 ;;
  esac
done

log()  { echo -e "\033[1;32m[install]\033[0m $*"; }
warn() { echo -e "\033[1;33m[install]\033[0m $*"; }
die()  { echo -e "\033[1;31m[install]\033[0m $*" >&2; exit 1; }

# ---------- 本地离线镜像加载（优先于网络拉取） ----------
load_local_images() {
  local dir="${IMAGES_DIR:-$ROOT/releases/images}"
  if [[ ! -d "$dir" ]]; then
    [[ -n "$IMAGES_DIR" ]] && warn "指定的镜像目录不存在: $dir"
    return 0
  fi
  command -v ctr >/dev/null 2>&1 || { warn "未找到 ctr，跳过本地镜像加载"; return 0; }
  local tars=("$dir"/*.tar)
  [[ -e "${tars[0]:-}" ]] || { warn "镜像目录内没有 .tar 文件: $dir"; return 0; }
  local loaded=0
  for tar in "${tars[@]}"; do
    log "本地加载镜像: $(basename "$tar")"
    if ctr -n k8s.io images import "$tar" >/tmp/ndr-ctr-import.log 2>&1; then
      loaded=$((loaded+1))
    elif grep -qiE "already exists|already used|already present" /tmp/ndr-ctr-import.log 2>/dev/null; then
      log "  镜像已存在，跳过"
    else
      warn "镜像加载失败 $(basename "$tar"): $(tail -1 /tmp/ndr-ctr-import.log)"
    fi
  done
  if [[ "$loaded" -gt 0 || -n "$IMAGES_DIR" ]]; then
    log "本地镜像加载完成（新加载 $loaded 个）✔"
  fi
}

# ---------- 环境预检 ----------
if [[ "$SKIP_CHECKS" != "1" ]]; then
  log "环境预检..."
  command -v kubectl >/dev/null || die "缺少 kubectl"
  command -v openssl >/dev/null || die "缺少 openssl"
  command -v python3 >/dev/null || die "缺少 python3"
  python3 -c "import yaml" 2>/dev/null || die "缺少 python3 pyyaml 模块"
  kubectl get nodes >/dev/null 2>&1 || die "kubectl 无法访问集群"
  if ! kubectl get nodes --no-headers 2>/dev/null | awk '$2 != "Ready" {exit 1}'; then
    die "存在非 Ready 节点，请先恢复集群"
  fi
  CPU=$(kubectl get nodes --no-headers -o custom-columns=:.status.allocatable.cpu 2>/dev/null | head -1)
  MEM_KI=$(kubectl get nodes --no-headers -o custom-columns=:.status.allocatable.memory 2>/dev/null | head -1)
  log "节点可用资源: CPU=${CPU} 内存=${MEM_KI}"
fi

# ---------- probe 配置 ----------
if [[ -z "$CONFIG_FILE" ]]; then
  CONFIG_FILE="$ROOT/configs/probe.yaml"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    cp "$ROOT/configs/probe.yaml.example" "$CONFIG_FILE"
    warn "已从示例创建 configs/probe.yaml，请填写实际参数后重试"
  fi
fi
[[ -f "$CONFIG_FILE" ]] || die "配置文件不存在: $CONFIG_FILE"

if [[ -n "$INTERFACE" ]]; then
  # 用命令行网卡覆盖配置（临时渲染）
  TMP_CFG=$(mktemp)
  sed "s/^\(\s*interface:\s*\).*/\1$INTERFACE/" "$CONFIG_FILE" > "$TMP_CFG"
  CONFIG_FILE="$TMP_CFG"
  log "镜像口: $INTERFACE"
fi

# ---------- 镜像 tag ----------
if [[ -n "$TAG" ]]; then
  [[ "$TAG" =~ ^[0-9a-f]{40}$ ]] || die "镜像 tag 应为 40 位 git sha（当前: $TAG），请用完整 commit hash"
  if [[ -f "$DEPLOY_DIR/kustomization.yaml" ]]; then
    sed -i.bak "s/\(newTag: \).*/\1$TAG/" "$DEPLOY_DIR/kustomization.yaml"
    rm -f "$DEPLOY_DIR/kustomization.yaml.bak"
    log "镜像 tag 覆盖为: $TAG"
  fi
fi

# 本地离线镜像优先加载（k8s 拉取策略 IfNotPresent，本地已有则不再走网络）
load_local_images

# ---------- 渲染 ConfigMap ----------
log "渲染 ConfigMap..."
python3 "$ROOT/releases/render-configs.py" "$CONFIG_FILE" "$DEPLOY_DIR/10-configmap.yaml"
[[ -f "$TMP_CFG" ]] && rm -f "$TMP_CFG"

# ---------- 凭据 ----------
log "准备凭据..."
if [[ ! -f "$DEPLOY_DIR/25-secret.yaml" ]]; then
  bash "$ROOT/releases/gen-secret.sh"
else
  log "25-secret.yaml 已存在，跳过生成"
fi

# ---------- 部署 ----------
log "创建命名空间/证书/全部资源..."
kubectl create ns "$NS" --dry-run=client -o yaml 2>/dev/null | kubectl apply -f - >/dev/null
if ! kubectl get secret nss-ndr-certs -n "$NS" >/dev/null 2>&1; then
  GEN_CERTS="$DEPLOY_DIR/gen-certs.sh"
  [[ -f "$GEN_CERTS" ]] || GEN_CERTS="$ROOT/releases/gen-certs.sh"
  bash "$GEN_CERTS" "$NS"
else
  log "证书 Secret 已存在，跳过"
fi

# fleet-init Job 不可变，重复部署时先删旧的已完成 Job
kubectl delete job nss-fleet-init -n "$NS" --ignore-not-found >/dev/null 2>&1 || true

kubectl apply -k "$DEPLOY_DIR"
log "资源已应用，等待组件就绪..."

# ---------- 等待就绪 ----------
deadline=$((SECONDS + TIMEOUT))
while [[ $SECONDS -lt $deadline ]]; do
  not_ready=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null |
    awk '$3 != "Running" && $3 != "Completed" {n++} END {print n+0}')
  if [[ "$not_ready" == "0" ]]; then
    log "全部组件就绪 ✔"
    break
  fi
  sleep 15
done
not_ready=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null |
  awk '$3 != "Running" && $3 != "Completed" {n++} END {print n+0}')
if [[ "$not_ready" != "0" ]]; then
  warn "部分组件未在超时时间内就绪（剩余 $not_ready 个）："
  kubectl get pods -n "$NS" | awk '$3 != "Running" && $3 != "Completed"'
  die "部署超时，请检查上述组件日志"
fi

# ---------- 访问信息 ----------
log "================ 部署完成 ================"
echo ""
echo "  探针管理后台 : http://<本机IP>:$MANAGER_PORT   （初始账号 admin / admin，登录后请改密）"
echo "  Kibana       : http://<本机IP>:30601/kibana   （elastic / nss-ndr@2026）"
echo "  NDR 看板     : 已内嵌于管理后台“可视化分析”菜单"
echo "  镜像口       : $INTERFACE"
echo "  探针 ID      : $(python3 -c "import yaml,sys; print(yaml.safe_load(open('$DEPLOY_DIR/10-configmap.yaml'))['data'].get('sensor_id',''))" 2>/dev/null)"
echo ""
echo "=========================================="
