#!/usr/bin/env bash
# ============================================================================
# 同步 Salt 引擎文件到数据总线宿主机
# ----------------------------------------------------------------------------
# 为什么需要：/opt/nss/ndr/salt/{file_roots,pillar_roots} 不在镜像里，
#   是部署时从仓库同步过去的（业务配置由 configs.sls 再下发到 /opt/nss/ndr/<app>）。
#   本脚本把仓库里的 state/jinja/业务配置模板一次性推过去，避免手工 scp 漏文件。
#
# 同步映射（与 salt fileserver 的路径约定一致）：
#   src/databus/salt/states/<f>             -> file_roots/databus/<f>
#   src/databus/salt/states/containers/<f>  -> file_roots/databus/containers/<f>
#   src/databus/salt/states/teardown/<f>    -> file_roots/databus/teardown/<f>
#   src/databus/salt/files/<...>            -> file_roots/databus/files/<...>
#   src/databus/salt/pillar.example         -> pillar_roots/databus.sls.example（仅模板）
#
# 注意：
#   - **不会覆盖** pillar_roots/databus.sls（含真实密钥，首次部署时手工生成）
#   - pillar_roots/top.sls 缺失时会自动创建
#
# 用法：
#   scripts/sync-salt.sh <user@host> [选项]
#     --prune           删除服务器上仓库已不存在的 .sls（默认只增量覆盖）
#     --with-images     额外把 docker/*.tar.gz 分片传到服务器并 docker load
#     --no-cache-clear  同步后不清理 salt master 的 fileserver 缓存
#     -h|--help
#
# 例：
#   SSH_PASS='qaz@7410' scripts/sync-salt.sh root@172.16.196.79
#   SSH_PASS='qaz@7410' scripts/sync-salt.sh root@172.16.196.79 --prune --with-images
#
# 环境变量：
#   SSH_PASS   如设置则用 sshpass 传密码（否则走 ssh 密钥/agent）
#   NSS_SALT_BASE  远端 salt 根，默认 /opt/nss/ndr/salt
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

HOST=""
PRUNE=0
WITH_IMAGES=0
CLEAR_CACHE=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prune) PRUNE=1 ;;
    --with-images) WITH_IMAGES=1 ;;
    --no-cache-clear) CLEAR_CACHE=0 ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "未知参数: $1" >&2; exit 2 ;;
    *) HOST="$1" ;;
  esac
  shift
done
[[ -n "$HOST" ]] || { echo "用法: $0 <user@host> [--prune] [--with-images]" >&2; exit 2; }

BASE="${NSS_SALT_BASE:-/opt/nss/ndr/salt}"
SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30)
[[ -n "${SSH_PASS:-}" ]] && SSH=(sshpass -p "$SSH_PASS" "${SSH[@]}")
RUN() { "${SSH[@]}" "$HOST" "$@"; }

SRC_STATES=src/databus/salt/states
SRC_FILES=src/databus/salt/files
SRC_PILLAR=src/databus/salt/pillar.example
[[ -d "$SRC_STATES" ]] || { echo "找不到 $SRC_STATES（请在仓库根目录运行）" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== 准备同步内容 =="
mkdir -p "$TMP/file_roots/databus" "$TMP/pillar_roots"
cp -a "$SRC_STATES/." "$TMP/file_roots/databus/"          # 顶层 flatten + 保留 containers/ teardown/
echo "   file_roots/databus: $(find "$TMP/file_roots/databus" -type f | wc -l | tr -d ' ') 个文件"
if [[ -d "$SRC_FILES" ]]; then
  mkdir -p "$TMP/file_roots/databus/files"
  cp -a "$SRC_FILES/." "$TMP/file_roots/databus/files/"
  echo "   file_roots/databus/files: $(find "$TMP/file_roots/databus/files" -type f | wc -l | tr -d ' ') 个文件"
fi
[[ -f "$SRC_PILLAR" ]] && cp "$SRC_PILLAR" "$TMP/pillar_roots/databus.sls.example"

echo "== 推送到 $HOST:$BASE =="
# macOS bsdtar 会打包 xattr（Linux 侧告警）→ 关掉；GNU tar 不认这两个参数
TAR_OPTS=()
tar --version 2>/dev/null | grep -qi bsdtar && TAR_OPTS=(--no-xattrs --no-mac-metadata)
COPYFILE_DISABLE=1 tar "${TAR_OPTS[@]}" -czf - -C "$TMP" . \
  | RUN "mkdir -p '$BASE' && tar xzf - -C '$BASE'"

# pillar top.sls：仅在缺失时创建（不动已有内容）
RUN "if [ ! -f '$BASE/pillar_roots/top.sls' ]; then
       printf 'base:\n  %s:\n    - databus\n' \"'*'\" > '$BASE/pillar_roots/top.sls'
       echo '   已创建 pillar_roots/top.sls'
     fi
     [ -f '$BASE/pillar_roots/databus.sls' ] || echo '   ⚠ 提醒: pillar_roots/databus.sls 不存在，需按 databus.sls.example 生成（含真实密钥）'"

if [[ "$PRUNE" == "1" ]]; then
  echo "== 清理服务器上仓库已不存在的 .sls =="
  # 只比对 databus/ 下的 .sls（不含 files/，那是业务配置，由 configs.sls 管理）
  find "$TMP/file_roots/databus" -name '*.sls' -o -name '*.jinja' | sed "s|$TMP/file_roots/databus/||" | sort > "$TMP/want.txt"
  RUN "cd '$BASE/file_roots/databus' && find . -name '*.sls' -o -name '*.jinja' | sed 's|^\./||' | sort" > "$TMP/have.txt"
  comm -13 "$TMP/want.txt" "$TMP/have.txt" | while read -r f; do
    [[ -n "$f" ]] && RUN "rm -f '$BASE/file_roots/databus/$f' && echo '   删除 $f'"
  done
fi

CACHE_CMD="true"
[[ "$CLEAR_CACHE" == "1" ]] && CACHE_CMD="docker exec nss-ndr-salt-master-api salt-run fileserver.clear_file_list_cache >/dev/null 2>&1 && echo '   已清理（master 会重新读取 state 文件）' || echo '   跳过（master 容器未运行或 runner 不可用）'"
RUN "echo '== 清理 fileserver 缓存 =='; $CACHE_CMD"

if [[ "$WITH_IMAGES" == "1" ]]; then
  echo "== 传输镜像包并 docker load =="
  shopt -s nullglob
  tars=(docker/*.tar.gz)
  [[ ${#tars[@]} -gt 0 ]] || { echo "   docker/ 下没有 *.tar.gz，跳过"; tars=(); }
  for t in "${tars[@]}"; do
    n="$(basename "$t")"
    sz=$(stat -f%z "$t" 2>/dev/null || stat -c%s "$t")
    echo "   -> $n ($((sz / 1048576))MB)"
    RUN "rm -rf /root/nss-ndr/images/chunks && mkdir -p /root/nss-ndr/images/chunks"
    # 8MB 分片：整文件传在弱网下容易卡死，分片单片可靠可重试
    split -b 8m "$t" "$TMP/${n}.part_"
    for p in "$TMP/${n}.part_"*; do
      pn="$(basename "$p")"
      for try in 1 2 3; do
        if sshpass -p "${SSH_PASS:-}" scp -o StrictHostKeyChecking=no -o ConnectTimeout=20 \
             "$p" "$HOST:/root/nss-ndr/images/chunks/$pn" >/dev/null 2>&1; then break; fi
        [[ $try == 3 ]] && { echo "      ✗ $pn 传输失败"; exit 1; }
        sleep 3
      done
    done
    rm -f "$TMP/${n}.part_"*
    RUN "cd /root/nss-ndr/images && cat chunks/${n}.part_* > '$n' && rm -rf chunks && \
         [ \"\$(stat -c %s '$n')\" = '$sz' ] && echo '      大小校验 ✓' && \
         docker load -i '$n' 2>&1 | tail -2"
  done
fi

echo ""
echo "== 完成 =="
RUN "ls '$BASE/file_roots/databus' | tr '\n' ' '; echo; ls '$BASE/pillar_roots'"
