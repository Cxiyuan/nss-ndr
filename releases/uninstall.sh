#!/usr/bin/env bash
# NSS-NDR 探针一键卸载脚本（只清理本项目，不影响其他业务）
# 用法:
#   bash releases/uninstall.sh [-y] [--keep-images] [--keep-manifests]
set -euo pipefail

NS="nss-ndr"
ASSUME_YES=0
KEEP_IMAGES=0
KEEP_MANIFESTS=0

usage() {
  echo "用法: $0 [选项]"
  echo "  -y, --yes              跳过确认"
  echo "  --keep-images          保留项目镜像（默认清理）"
  echo "  --keep-manifests       保留 /opt/nss-deploy 与 /opt/so（默认清理）"
  echo "  -h, --help             帮助"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    --keep-images) KEEP_IMAGES=1; shift ;;
    --keep-manifests) KEEP_MANIFESTS=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "未知参数: $1"; usage 1 ;;
  esac
done

log()  { echo -e "\033[1;36m[uninstall]\033[0m $*"; }
warn() { echo -e "\033[1;33m[uninstall]\033[0m $*"; }
die()  { echo -e "\033[1;31m[uninstall]\033[0m $*" >&2; exit 1; }

if [[ "$ASSUME_YES" != "1" ]]; then
  echo "本操作将删除命名空间 $NS（含全部项目组件与数据卷）以及项目镜像/目录。"
  read -r -p "确认继续? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "已取消"; exit 0; }
fi

command -v kubectl >/dev/null || die "缺少 kubectl"

# ---------- 1. 删除命名空间 ----------
if kubectl get ns "$NS" >/dev/null 2>&1; then
  log "删除命名空间 $NS..."
  kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
  deadline=$((SECONDS + 120))
  while [[ $SECONDS -lt $deadline ]]; do
    if ! kubectl get ns "$NS" >/dev/null 2>&1; then
      log "命名空间已删除 ✔"
      break
    fi
    sleep 5
  done
  # 超时则强制清理残留 pod
  if kubectl get ns "$NS" >/dev/null 2>&1; then
    warn "命名空间 Terminating 超时，强制清理残留 pod..."
    kubectl delete pod -n "$NS" --all --force --grace-period=0 >/dev/null 2>&1 || true
    sleep 15
  fi
else
  log "命名空间不存在，跳过"
fi

# ---------- 2. 清理残留容器 ----------
log "清理残留容器..."
for c in $(crictl ps -a -q --label "io.kubernetes.pod.namespace=$NS" 2>/dev/null); do
  crictl stop -t 2 "$c" >/dev/null 2>&1 || true
  crictl rm -f "$c" >/dev/null 2>&1 || true
done

# ---------- 3. 清理项目镜像 ----------
if [[ "$KEEP_IMAGES" != "1" ]]; then
  log "清理项目镜像..."
  ctr -n k8s.io images ls 2>/dev/null | grep "ghcr.io/cxiyuan/nss-ndr/" | awk '{print $1}' | sort -u |
    while read -r img; do ctr -n k8s.io images rm "$img" >/dev/null 2>&1 || true; done
  # 基础镜像（digest 引用形式，按镜像名前缀匹配删除）
  for prefix in \
    docker.elastic.co/elasticsearch/elasticsearch \
    docker.io/library/redis \
    docker.io/library/busybox; do
    ctr -n k8s.io images ls 2>/dev/null | awk '{print $1}' | sort -u |
      grep "^$prefix" | while read -r img; do
        ctr -n k8s.io images rm "$img" >/dev/null 2>&1 || true
      done
  done
  # CRI 缓存里的 <none> 残留
  crictl images 2>/dev/null | awk '$1=="<none>" {print $3}' | while read -r id; do
    crictl rmi "$id" >/dev/null 2>&1 || true
  done
  log "镜像清理完成 ✔"
fi

# ---------- 4. 清理部署目录 ----------
if [[ "$KEEP_MANIFESTS" != "1" ]]; then
  for d in /opt/nss-deploy /opt/so; do
    if [[ -d "$d" ]]; then
      warn "移除 $d"
      rm -rf "$d"
    fi
  done
fi

# ---------- 5. 验证 ----------
log "验证残留..."
echo "  namespace: $(kubectl get ns "$NS" 2>&1 | tail -1)"
echo "  项目镜像: $(ctr -n k8s.io images ls 2>/dev/null | grep -c 'ghcr.io/cxiyuan/nss-ndr/' || true) 个"
echo "  残留容器: $(crictl ps -a --label "io.kubernetes.pod.namespace=$NS" 2>/dev/null | wc -l) 个"
echo ""
log "卸载完成 ✔（其他业务未受影响）"
