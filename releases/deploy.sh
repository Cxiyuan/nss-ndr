#!/usr/bin/env bash
# NSS-NDR 探针统一部署脚本（docker-compose 版，2026-08-16 起替代 k3s）
#
# 用法:
#   bash releases/deploy.sh install -i enp5s0 [--config configs/probe.yaml] [--manager-port 30603]
#   bash releases/deploy.sh uninstall [-y]
#   bash releases/deploy.sh save-images [--tag <sha>] [--out <dir>] [--skip-base]
#   bash releases/deploy.sh load-images [--dir <dir>]
#   bash releases/deploy.sh render <probe.yaml> [--out <dir>]
#   bash releases/deploy.sh help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/deploy/docker"
NS="nss-ndr"
NDR_HOME="/opt/ndr"                     # 数据根目录（nsm/so/es-data 等）
CONF_ROOT="$NDR_HOME/so/conf"           # 渲染后的配置目录

log()  { echo -e "\033[1;32m[deploy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[deploy]\033[0m $*"; }
die()  { echo -e "\033[1;31m[deploy]\033[0m $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
NSS-NDR 探针统一部署脚本（docker-compose）

用法:
  bash releases/deploy.sh install -i <网卡> [选项]
      -i, --interface <网卡>   抓包网卡（必填，如 enp5s0/eth1）
      -c, --config <文件>      probe 配置（默认 configs/probe.yaml，不存在则从示例复制）
      -p, --manager-port <端口> 管理后台端口（默认 30603）
      --skip-checks            跳过环境预检

  bash releases/deploy.sh uninstall [-y]
  bash releases/deploy.sh save-images [--tag <sha>] [--out <dir>] [--skip-base]
  bash releases/deploy.sh load-images [--dir <dir>]
  bash releases/deploy.sh render <probe.yaml> [--out <dir>]
  bash releases/deploy.sh help
EOF
  exit "${1:-0}"
}

# ============ 配置渲染（生成 /opt/ndr/so/conf 目录）============
render_conf() {
  local cfg="$1" out="${2:-$CONF_ROOT}"
  mkdir -p "$out/strelka" "$out/policy/securityonion/file-extraction" "$out/policy/cve-2020-0601" "$out/policy/intel"
  python3 - "$ROOT" "$cfg" "$out" <<'PYEOF'
import math, os, shutil, sys
try:
    import yaml
except ImportError:
    sys.exit("缺少 pyyaml，请先安装：pip3 install pyyaml")

root, cfg_path, out = sys.argv[1], sys.argv[2], sys.argv[3]

def render(src, dst, ctx=None):
    with open(os.path.join(root, src), encoding="utf-8") as f:
        content = f.read()
    if ctx:
        for k, v in ctx.items():
            content = content.replace("${" + k + "}", v)
    with open(os.path.join(out, dst), "w", encoding="utf-8") as f:
        f.write(content)

def copy_tree(src_dir, dst_rel):
    base = os.path.join(root, src_dir)
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), base)
            dst = os.path.join(out, dst_rel, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(dirpath, name), dst)

cfg = yaml.safe_load(open(cfg_path, encoding="utf-8"))
probe, suri, zeek = cfg["probe"], cfg["suricata"], cfg["zeek"]
pcap = suri.get("pcap", {})
if not probe.get("interface"):
    sys.exit("错误: probe.interface 未配置（如 enp5s0）")
threads = int(suri.get("af_packet_threads", 4))
file_size_mb = int(pcap.get("file_size_mb", 1000))
storage_gb = int(pcap.get("storage_limit_gb", 500))
max_files = max(1, math.ceil(storage_gb * 1000 / file_size_mb / threads))
ctx = {
    "INTERFACE": probe["interface"],
    "THREADS": str(threads),
    "HOME_NET": "'[" + ",".join(probe["home_net"]) + "]'",
    "EXTERNAL_NET": str(probe.get("external_net", "any")),
    "PCAP_ENABLED": "yes" if pcap.get("enabled", True) else "no",
    "PCAP_FILE_SIZE_MB": str(file_size_mb),
    "PCAP_COMPRESSION": str(pcap.get("compression", "none")),
    "PCAP_MAX_FILES": str(max_files),
    "WORKERS": str(zeek.get("workers", 4)),
    "BUFFER_SIZE": str(zeek.get("buffer_size", "128*1024*1024")),
    "LOG_ROTATION_INTERVAL": str(zeek.get("log_rotation_interval_s", 3600)),
    "ZEEK_NETWORKS": "\n".join(f"{n} Private_IP_Space" for n in probe["home_net"]),
}
render("images/suricata/files/suricata.yaml", "suricata.yaml", ctx)
render("images/suricata/files/threshold.conf", "threshold.conf")
render("images/zeek/files/local.zeek", "local.zeek")
render("images/zeek/files/node.cfg", "node.cfg")
render("images/zeek/files/zeekctl.cfg", "zeekctl.cfg")
render("images/zeek/files/networks.cfg", "networks.cfg")
render("images/zeek/files/config.zeek", "config.zeek")
render("images/filebeat/filebeat.yml", "filebeat.yml")
copy_tree("images/zeek/files/policy", "policy")
for k, rel in {
    "backend.yaml": "images/strelka-backend/files/backend.yaml",
    "logging.yaml": "images/strelka-backend/files/logging.yaml",
    "passwords.dat": "images/strelka-backend/files/passwords.dat",
    "frontend.yaml": "images/strelka-manager/files/frontend.yaml",
    "filestream.yaml": "images/strelka-manager/files/filestream.yaml",
    "manager.yaml": "images/strelka-manager/files/manager.yaml",
}.items():
    render(rel, "strelka/" + k)
render("images/strelka-backend/files/taste/taste.yara", "strelka/taste.yara")
shutil.copyfile(cfg_path, os.path.join(out, "probe.yaml"))
print(f"配置已渲染到 {out}（{len(ctx)+1} 项，接口={ctx['INTERFACE']}）")
PYEOF
}

# ============ 凭据 / .env ============
gen_env() {
  local env_file="$COMPOSE_DIR/.env"
  if [[ -f "$env_file" ]]; then
    log "$env_file 已存在，跳过生成"
    return 0
  fi
  cat > "$env_file" <<EOF
# 自动生成（deploy.sh）；elastic 密码固定默认值，其余随机
PROBE_ID=nss-001
INTERFACE=CHANGE_ME_INTERFACE
ELASTIC_PASSWORD=nss-ndr@2026
FB_PASSWORD=$(openssl rand -hex 16)
XDR_PASSWORD=$(openssl rand -hex 16)
MANAGER_PORT=30603
ES_HOST=http://elasticsearch:9200
ES_USERNAME=xdr-push
ES_HEAP_GB=2
LLM_URL=http://host.docker.internal:11434/v1/chat/completions
LLM_MODEL=
XDR_WEBHOOK_URL=
XDR_WEBHOOK_SECRET=
XDR_TASK_TOKEN=
EOF
  log "已生成 $env_file（elastic 密码 nss-ndr@2026，其余随机）"
}

# ============ install ============
cmd_install() {
  local interface="" config_file="" manager_port=30603 skip_checks=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -i|--interface) interface="$2"; shift 2 ;;
      -c|--config) config_file="$2"; shift 2 ;;
      -p|--manager-port) manager_port="$2"; shift 2 ;;
      --skip-checks) skip_checks=1; shift ;;
      -h|--help) usage 0 ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  [[ -n "$interface" ]] || die "缺少 -i/--interface（抓包网卡必填）"

  if [[ "$skip_checks" != "1" ]]; then
    log "环境预检..."
    command -v docker >/dev/null || die "缺少 docker（请先安装：curl -fsSL https://get.docker.com | sh）"
    docker compose version >/dev/null 2>&1 || die "缺少 docker compose 插件"
    [[ -f /etc/os-release ]] && . /etc/os-release
    if [[ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]]; then
      log "设置 vm.max_map_count=262144（ES 需要）..."
      sysctl -w vm.max_map_count=262144 >/dev/null
      echo "vm.max_map_count=262144" > /etc/sysctl.d/99-nss-ndr.conf 2>/dev/null || true
    fi
  fi

  # probe 配置
  if [[ -z "$config_file" ]]; then
    config_file="$ROOT/configs/probe.yaml"
    [[ -f "$config_file" ]] || { cp "$ROOT/configs/probe.yaml.example" "$config_file"; warn "已创建 configs/probe.yaml，请检查参数"; }
  fi
  [[ -f "$config_file" ]] || die "配置文件不存在: $config_file"

  log "渲染配置到 $CONF_ROOT ..."
  render_conf "$config_file" "$CONF_ROOT"

  log "准备 .env ..."
  gen_env
  local env_file="$COMPOSE_DIR/.env"
  sed -i.bak "s/^INTERFACE=.*/INTERFACE=$interface/; s/^MANAGER_PORT=.*/MANAGER_PORT=$manager_port/" "$env_file"
  rm -f "$env_file.bak"
  sed -i.bak "s/^PROBE_ID=.*/PROBE_ID=$(python3 -c "import yaml;print(yaml.safe_load(open('$config_file'))['probe']['id'])" 2>/dev/null || echo nss-001)/" "$env_file"
  rm -f "$env_file.bak"

  mkdir -p "$NDR_HOME/es-data" "$NDR_HOME/nsm" "$NDR_HOME/so" "$NDR_HOME/yara" "$NDR_HOME/filebeat-data"
  log "启动 docker compose ..."
  (cd "$COMPOSE_DIR" && docker compose up -d)
  log "等待组件就绪..."
  local deadline=$((SECONDS + 600))
  while [[ $SECONDS -lt $deadline ]]; do
    if curl -sf -m 3 "http://127.0.0.1:$manager_port/api/health" >/dev/null 2>&1; then
      log "管理后台就绪 ✔"
      break
    fi
    sleep 10
  done
  curl -sf -m 3 "http://127.0.0.1:$manager_port/api/health" >/dev/null 2>&1 || warn "管理后台未在超时内就绪，请检查 docker compose ps"

  log "================ 部署完成 ================"
  echo ""
  echo "  探针管理后台 : http://<本机IP>:$manager_port   （初始账号 admin / admin，登录后请改密）"
  echo "  镜像口       : $interface"
  echo "  XDR 任务接口 : POST http://<本机IP>:$manager_port/api/xdr/task 与 /api/xdr/agent/task（Bearer 令牌）"
  echo "  常用命令     : cd $COMPOSE_DIR && docker compose ps / logs -f <服务>"
  echo ""
}

# ============ uninstall ============
cmd_uninstall() {
  local assume_yes=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes) assume_yes=1; shift ;;
      -h|--help) usage 0 ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  if [[ "$assume_yes" != "1" ]]; then
    echo "将停止并删除本项目全部容器/数据（$NDR_HOME）。"
    read -r -p "确认继续? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "已取消"; exit 0; }
  fi
  if command -v docker >/dev/null 2>&1 && [[ -f "$COMPOSE_DIR/docker-compose.yml" ]]; then
    log "停止并删除容器..."
    (cd "$COMPOSE_DIR" && docker compose down -v --remove-orphans 2>/dev/null || true)
  fi
  log "清理数据目录 $NDR_HOME ..."
  if [[ -d "$NDR_HOME" ]]; then
    rm -rf "$NDR_HOME"
  fi
  log "卸载完成 ✔（k3s/rancher 及其他业务未受影响）"
}

# ============ save-images / load-images ============
cmd_save_images() {
  local tag="" out="" include_base=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag) tag="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      --skip-base) include_base=0; shift ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  command -v skopeo >/dev/null || die "缺少 skopeo（brew install skopeo / apt install skopeo）"
  [[ -z "$tag" ]] && tag=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo latest)
  out="${out:-$ROOT/releases/images}"
  mkdir -p "$out"
  local project_images=(
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-suricata"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-zeek"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-es-init"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-mcp-server"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-ndr-agent"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-ndr-manager"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-xdr-push"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-cleaner"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-strelka-backend"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-strelka-manager"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-strelka-rules"
    "ghcr.io/cxiyuan/nss-ndr/nss-ndr-filecheck"
  )
  local base_images=(
    "docker.elastic.co/beats/filebeat:9.3.3"
    "docker.elastic.co/elasticsearch/elasticsearch:9.3.3"
    "docker.io/library/redis:7-alpine"
    "docker.io/library/busybox:1.36"
  )
  save_one() {
    local src="$1" out_file="$2"
    [[ -f "$out_file" && -s "$out_file" ]] && { echo "已存在: $(basename "$out_file")"; return 0; }
    echo "导出: $src"
    skopeo copy --retry-times=3 --override-os linux --override-arch amd64 \
      "docker://$src" "docker-archive:$out_file:$src"
  }
  for img in "${project_images[@]}"; do
    save_one "${img}:${tag:-latest}" "$out/$(basename "$img")-${tag:0:12}.tar"
  done
  if [[ "$include_base" == "1" ]]; then
    for b in "${base_images[@]}"; do
      save_one "$b" "$out/$(echo "$b" | tr '/:' '__').tar"
    done
  fi
  echo "完成：镜像已导出到 $out（docker load -i <tar> 加载）"
}

cmd_load_images() {
  local dir="$ROOT/releases/images"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      *) dir="$1"; shift ;;
    esac
  done
  command -v docker >/dev/null || die "缺少 docker"
  local loaded=0
  for tar in "$dir"/*.tar; do
    [[ -f "$tar" ]] || continue
    log "docker load: $(basename "$tar")"
    if docker load -i "$tar" >/tmp/ndr-docker-load.log 2>&1; then
      loaded=$((loaded+1))
    else
      warn "加载失败 $(basename "$tar"): $(tail -1 /tmp/ndr-docker-load.log)"
    fi
  done
  log "镜像加载完成（$loaded 个）✔"
}

# ============ 入口 ============
cmd="${1:-help}"
shift 2>/dev/null || true
case "$cmd" in
  install) cmd_install "$@" ;;
  uninstall) cmd_uninstall "$@" ;;
  save-images) cmd_save_images "$@" ;;
  load-images) cmd_load_images "$@" ;;
  render) cmd_render=1; cfg="${1:-}"; out=""; shift 2>/dev/null || true
          while [[ $# -gt 0 ]]; do case "$1" in --out) out="$2"; shift 2;; *) cfg="$1"; shift;; esac; done
          [[ -n "$cfg" ]] || { echo "用法: deploy.sh render <probe.yaml> [--out <dir>]"; exit 1; }
          render_conf "$cfg" "${out:-$CONF_ROOT}" ;;
  help|-h|--help|"") usage 0 ;;
  *) echo "未知命令: $cmd"; usage 1 ;;
esac
