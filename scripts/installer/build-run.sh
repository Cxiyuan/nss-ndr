#!/usr/bin/env bash
# ============================================================
# 生成 nss-ndr 部署安装包（.run 自解压格式）
#
# 结构：头部 Shell 脚本 + 尾部 tar 载荷（install.sh + images/*.tar + salt/）
# 用法：./build-run.sh [输出目录] [版本号]
#   输出目录默认 部署发布/（run 包放在部署发布根目录）
#   版本号默认当天日期
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALLER_DIR="$ROOT_DIR/scripts/installer"
IMAGES_DIR="$ROOT_DIR/部署发布/容器镜像"
OUT_DIR="${1:-$ROOT_DIR/部署发布}"
VERSION="${2:-$(date +%Y%m%d)}"

[[ -f "$INSTALLER_DIR/install.sh" ]] || { echo "[ERROR] 缺少 install.sh: $INSTALLER_DIR" >&2; exit 1; }
[[ -d "$IMAGES_DIR" ]] || { echo "[ERROR] 未找到镜像目录: $IMAGES_DIR" >&2; exit 1; }

TARS=()
while IFS= read -r t; do TARS+=("$t"); done < <(find "$IMAGES_DIR" -maxdepth 1 -name '*.tar' | sort)
[[ ${#TARS[@]} -gt 0 ]] || { echo "[ERROR] 镜像目录下没有 .tar 镜像包" >&2; exit 1; }

WORK="$(mktemp -d /tmp/nss-ndr-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/payload/images"

cp "$INSTALLER_DIR/install.sh" "$WORK/payload/install.sh"
chmod +x "$WORK/payload/install.sh"
cp "${TARS[@]}" "$WORK/payload/images/"
mkdir -p "$WORK/payload/salt"
cp -r "$ROOT_DIR/src/agent/salt" "$WORK/payload/salt/agent"
cp -r "$ROOT_DIR/src/databus/salt" "$WORK/payload/salt/databus"

# ---------- 生成头部脚本 ----------
cat > "$WORK/header.sh" <<'EOF'
#!/usr/bin/env bash
# ============================================================
# nss-ndr 深瞳安全分析智能体 · 部署安装包
# 目标平台：Linux Anolis OS / x86_64（自解压格式）
#
# 用法：sudo ./<本文件>.run [安装目录]
#   [安装目录] 默认 /opt/nss-agent
#   环境变量 NSS_NIC=网卡名 可跳过网卡交互选择
# ============================================================
set -euo pipefail

PAYLOAD_LINE=__PAYLOAD_LINE__

if [[ ${EUID} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 或 sudo 执行本安装包" >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/nss-ndr-installer.XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "==> 解压安装包载荷 ..."
tail -n +"${PAYLOAD_LINE}" "$0" | tar xf - -C "$WORKDIR" || {
  echo "[ERROR] 载荷解压失败（文件可能已损坏）" >&2
  exit 1
}

exec bash "$WORKDIR/install.sh" "$@"
# ============ 以下为载荷数据（构建时自动追加，请勿编辑） ============
EOF

HEADER_LINES="$(wc -l < "$WORK/header.sh")"
PAYLOAD_LINE="$((HEADER_LINES + 1))"
sed "s/__PAYLOAD_LINE__/${PAYLOAD_LINE}/" "$WORK/header.sh" > "$WORK/run.sh"

# ---------- 拼接载荷并输出 ----------
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/nss-ndr-installer-${VERSION}.run"
(
  cd "$WORK"
  cat run.sh
  tar cf - -C payload .
) > "$OUT_FILE"
chmod +x "$OUT_FILE"

echo "==> 安装包生成完成：$OUT_FILE"
echo "    包含镜像（$((${#TARS[@]})) 个）："
for t in "${TARS[@]}"; do
  echo "      - $(basename "$t")"
done
echo "    包含 Salt 状态：src/agent/salt -> salt/agent/，src/databus/salt -> salt/databus/"
echo "    安装包大小：$(du -h "$OUT_FILE" | cut -f1)"
