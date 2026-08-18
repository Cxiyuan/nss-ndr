#!/usr/bin/env bash
# NSS-NDR 发布包打包脚本：把部署脚本 + docker-compose 清单 + 离线镜像包
# 打包为 Linux 自解压 .run 文件（Bash 头 + tar.gz，类 makeself）。
#
# 用法:
#   bash releases/package-release.sh [--tag <版本>] [--out <dir>]
#
# 产物: releases/nss-ndr-<tag>.run （Linux 上 chmod +x 后直接运行）
#   ./nss-ndr-<tag>.run                      # 解压到 ./nss-ndr
#   ./nss-ndr-<tag>.run --dir /opt/nss-ndr   # 解压到指定目录
#   ./nss-ndr-<tag>.run install -i enp5s0    # 解压并直接部署
#   ./nss-ndr-<tag>.run --list               # 查看包内容
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG=""
OUT=""

usage() {
  echo "用法: $0 [--tag <版本>] [--out <dir>]"
  echo "  --tag <版本>   发布版本号（默认当前 git sha 前 12 位）"
  echo "  --out <dir>    输出目录（默认 $ROOT/releases）"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "未知参数: $1"; usage 1 ;;
  esac
done

[[ -z "$TAG" ]] && TAG=$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo "dev")
OUT="${OUT:-$ROOT/releases}"
IMAGES_DIR="$ROOT/releases/images"

# ---------- 校验离线镜像包 ----------
if ! ls "$IMAGES_DIR"/*.tar >/dev/null 2>&1; then
  echo "未找到离线镜像包（$IMAGES_DIR/*.tar），请先执行 deploy.sh save-images"
  exit 1
fi
echo "离线镜像包: $(ls "$IMAGES_DIR"/*.tar | wc -l | tr -d ' ') 个 tar"

# ---------- 组装发布内容 ----------
STAGE=$(mktemp -d /tmp/nss-ndr-pack.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/deploy/docker" "$STAGE/configs" "$STAGE/test" "$STAGE/releases/images"

cp "$ROOT/releases/deploy.sh" "$STAGE/deploy.sh"
cp "$ROOT/deploy/docker/docker-compose.yml" "$STAGE/deploy/docker/"
cp "$ROOT/deploy/docker/.env.example" "$STAGE/deploy/docker/"
cp "$ROOT/configs/probe.yaml.example" "$STAGE/configs/"
cp "$ROOT/test/traffic-test.sh" "$STAGE/test/"
cp "$IMAGES_DIR"/*.tar "$STAGE/releases/images/"
cp "$IMAGES_DIR/manifest.txt" "$STAGE/releases/images/" 2>/dev/null || true
chmod +x "$STAGE/deploy.sh" "$STAGE/test/traffic-test.sh"

# ---------- 生成自解压头 ----------
HEADER="$STAGE/header.sh"
cat > "$HEADER" <<'RUNEOF'
#!/bin/sh
# NSS-NDR 探针发布包（自解压，面向 Linux）
set -e
SELF="$0"
TARGET=""
CMD=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) TARGET="$2"; shift 2 ;;
    --list)
      LINE=$(awk '/^__ARCHIVE_BELOW__/ {print NR+1; exit}' "$SELF")
      tail -n +"$LINE" "$SELF" | tar -tf - | sed 's/^/  /'
      exit 0
      ;;
    -h|--help)
      echo "NSS-NDR 探针发布包"
      echo "用法:"
      echo "  $0 [--dir <解压目录>] install -i <网卡> [-y]"
      echo "  $0 [--dir <解压目录>] uninstall -y"
      echo "  $0 [--dir <解压目录>] <其他 deploy.sh 子命令>"
      echo "  $0 --list                    查看包内容"
      exit 0
      ;;
    install)
      NEED_I=1; [ -n "$2" ] && { case "$2" in -i|--interface) NEED_I=0;; esac; }
      [ $NEED_I -eq 1 ] && { echo "错误: install 必须指定 -i <网卡>"; exit 1; }
      break ;;
    uninstall|save-images|load-images|render)
      break ;;
    *) echo "未知命令: $1"; exit 1 ;;
  esac
done
CMD="$*"

# Docker 预检（install/uninstall/load-images 前）
case "$CMD" in
  install*|uninstall*|load-images*)
    command -v docker >/dev/null 2>&1 || { echo "错误: 未检测到 docker，请先安装 Docker（https://get.docker.com）"; exit 1; }
    docker compose version >/dev/null 2>&1 || { echo "错误: 未检测到 docker compose v2 插件"; exit 1; }
    ;;
esac

[ -z "$TARGET" ] && TARGET="./nss-ndr"
echo "解压发布包到 $TARGET ..."
mkdir -p "$TARGET"
# 目录非空警告
if [ -n "$(ls -A "$TARGET" 2>/dev/null)" ]; then
  echo "警告: 目标目录 $TARGET 非空，解压会合并覆盖现有文件" >&2
  echo "  （如需全新部署，请先清空该目录或指定新目录）" >&2
fi
# 磁盘空间预检（解压 5.6GB + ES+pcap 至少需 15GB 可用）
FREE_GB=$(df -PB 1G "$TARGET" 2>/dev/null | tail -1 | awk "{print \\\$4}" | sed "s/G//")
if [ -n "$FREE_GB" ] && [ "$FREE_GB" -lt 15 ] 2>/dev/null; then
  echo "错误: 目标目录所在磁盘仅 ${FREE_GB}GB 可用，至少需要 15GB" >&2
  exit 1
fi
LINE=$(awk '/^__ARCHIVE_BELOW__/ {print NR+1; exit}' "$SELF")
tail -n +"$LINE" "$SELF" | tar -xf - -C "$TARGET"
chmod +x "$TARGET/deploy.sh" "$TARGET/test/traffic-test.sh" 2>/dev/null || true
echo "解压完成 ✔"

if [ -n "$CMD" ]; then
  echo "执行: deploy.sh $CMD"
  exec sh "$TARGET/deploy.sh" $CMD
fi

echo ""
echo "部署：cd $TARGET && ./deploy.sh install -i <网卡>   （-y 非交互）"
echo "卸载：cd $TARGET && ./deploy.sh uninstall -y"
echo "离线镜像已包含在包内，install 会自动本地加载（不依赖网络拉取）"
exit 0
__ARCHIVE_BELOW__
RUNEOF

# ---------- 打包（头 + tar.gz） ----------
RUN_FILE="$OUT/nss-ndr-$TAG.run"
echo "打包 $RUN_FILE ..."
(
  cd "$STAGE"
  tar -cf "$STAGE/archive.tar" deploy.sh deploy configs test releases/images
)
cat "$HEADER" "$STAGE/archive.tar" > "$RUN_FILE"
chmod +x "$RUN_FILE"

SIZE_MB=$(du -m "$RUN_FILE" | cut -f1)
echo ""
echo "完成: $RUN_FILE （${SIZE_MB}MB）"
echo "用法:"
echo "  chmod +x $RUN_FILE"
echo "  $RUN_FILE install -i enp5s0      # 解压并部署"
echo "  $RUN_FILE --dir /opt/nss-ndr     # 仅解压"
