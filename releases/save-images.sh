#!/usr/bin/env bash
# NSS-NDR 镜像导出脚本：把当前 pin 版本的项目镜像（+基础镜像）导出为 docker-archive tar，
# 保存到 releases/images/，供 install.sh 在部署机上本地加载（离线/加速部署，不依赖网络拉取）。
# 依赖：skopeo（brew install skopeo / apt install skopeo）
# 用法:
#   bash releases/save-images.sh [--tag <sha>] [--out <dir>] [--include-base] [--skip-base]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/deploy/k3s"

die() { echo -e "\033[1;31m[save-images]\033[0m $*" >&2; exit 1; }

TAG=""
OUT=""
INCLUDE_BASE=1

usage() {
  echo "用法: $0 [选项]"
  echo "  --tag <sha>       导出的镜像 tag（默认读取 deploy/k3s/kustomization.yaml 的 newTag）"
  echo "  --out <dir>       输出目录（默认 releases/images）"
  echo "  --skip-base       跳过基础镜像（ES/redis/busybox）"
  echo "  -h, --help        帮助"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --skip-base) INCLUDE_BASE=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "未知参数: $1"; usage 1 ;;
  esac
done

command -v skopeo >/dev/null || die "缺少 skopeo（brew install skopeo）"

if [[ -z "$TAG" ]]; then
  TAG=$(grep -m1 "newTag:" "$DEPLOY_DIR/kustomization.yaml" | awk '{print $2}')
fi
[[ "$TAG" =~ ^[0-9a-f]{40}$ ]] || { echo "镜像 tag 无效: $TAG"; exit 1; }
OUT="${OUT:-$ROOT/releases/images}"
mkdir -p "$OUT"

# 项目镜像（从 kustomization images 段提取）
PROJECT_IMAGES=()
while IFS= read -r img; do
  PROJECT_IMAGES+=("$img")
done < <(grep "name: ghcr.io/cxiyuan/nss-ndr" "$DEPLOY_DIR/kustomization.yaml" | sed 's/.*name: //' | sort -u)
# 基础镜像（部署清单里引用的非项目镜像）
BASE_IMAGES=(
  "docker.elastic.co/elasticsearch/elasticsearch:9.3.3"
  "docker.io/library/redis:7-alpine"
  "docker.io/library/busybox:1.36"
)

save_one() {
  local src="$1" out_file="$2"
  if [[ -f "$out_file" ]]; then
    echo "已存在，跳过: $(basename "$out_file")"
    return 0
  fi
  echo "导出: $src -> $(basename "$out_file")"
  skopeo copy --retry-times=3 \
    --override-os linux --override-arch amd64 \
    "docker://$src" "docker-archive:$out_file:$src"
}

total=0
for img in "${PROJECT_IMAGES[@]}"; do
  name=$(basename "$img")
  save_one "${img}:${TAG}" "$OUT/${name}-${TAG:0:12}.tar"
  total=$((total+1))
done

if [[ "$INCLUDE_BASE" == "1" ]]; then
  for b in "${BASE_IMAGES[@]}"; do
    name=$(echo "$b" | tr '/:' '__')
    save_one "$b" "$OUT/${name}.tar"
    total=$((total+1))
  done
fi

# 写入清单（install.sh 按清单加载，避免把无关 tar 混入）
{
  echo "# NSS-NDR 离线镜像包（tag=$TAG，生成时间 $(date -u +%Y-%m-%dT%H:%M:%SZ)）"
  for img in "${PROJECT_IMAGES[@]}"; do
    echo "${img}:${TAG}"
  done
  if [[ "$INCLUDE_BASE" == "1" ]]; then
    for b in "${BASE_IMAGES[@]}"; do
      echo "$b"
    done
  fi
} > "$OUT/manifest.txt"

echo ""
echo "完成：共 $total 个镜像已导出到 $OUT"
echo "部署机离线安装：将 releases/images 目录随代码一起拷贝到部署机，install.sh 会自动本地加载"
