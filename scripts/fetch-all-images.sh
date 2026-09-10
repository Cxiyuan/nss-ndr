#!/usr/bin/env bash
# ============================================================================
# 在"网络正常"的机器上批量下载本项目所需镜像为 OCI tar（存到 docker/）
# ----------------------------------------------------------------------------
# 背景：服务器连 ghcr.io / nju 极慢且不稳定，镜像拉取几乎不可用。
#       改为本机下载 tar → scp → 服务器 docker load。
#
# 用法：bash scripts/fetch-all-images.sh [输出目录，默认 docker]
# ============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-docker}"
mkdir -p "$OUT"

# 与 pillar databus:images 保持一致（CI 推到 ghcr.io，nju 是镜像站）
IMAGES=(
  "zeek-databus:8.2.2"
  "elasticsearch:9.5.2"
  "kibana:9.5.2"
  "elastic-agent-zeek:9.5.2"
  "fleet-server:9.5.2"
  "logstash-databus:9.5.2"
  "redis-databus:8.10.1"
  "llm-server:latest"
  "salt:latest"
  "vault:latest"
)

NS_GHCR="cxiyuan/nss-ndr-public"
NS_NJU="ghcr.nju.edu.cn/cxiyuan/nss-ndr-public"

fail=0
for spec in "${IMAGES[@]}"; do
  name="${spec%%:*}"
  tag="${spec##*:}"
  tar="${OUT}/${name}-${tag}.tar.gz"
  if [[ -s "$tar" ]]; then
    echo "== 跳过（已存在）$tar ($(du -h "$tar" | cut -f1))"
    continue
  fi
  echo "== 下载 ${name}:${tag} ..."
  if python3 scripts/fetch-image.py "${NS_GHCR}/${name}" "$tag" "$tar" \
       "${NS_NJU}/${name}:${tag}" "ghcr.io/${NS_GHCR}/${name}:${tag}"; then
    echo "   ✓ $(du -h "$tar" | cut -f1)"
  else
    echo "   ✗ 失败: ${name}:${tag}"
    fail=$((fail + 1))
    rm -f "$tar"
  fi
done

echo ""
echo "=== 完成（失败 $fail 个）==="
ls -lh "$OUT"/*.tar.gz 2>/dev/null | awk '{print "  " $9 "  " $5}'
