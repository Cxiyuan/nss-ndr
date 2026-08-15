#!/usr/bin/env bash
# NSS-NDR 探针统一部署脚本（一个文件完成安装/卸载/镜像导出/离线加载/配置渲染）
#
# 用法:
#   bash releases/deploy.sh install -i enp5s0 [--config configs/probe.yaml] [--tag <sha>] [--manager-port 30603] [--timeout 1800] [--images <dir>] [--skip-checks]
#   bash releases/deploy.sh uninstall [-y] [--keep-images] [--keep-manifests]
#   bash releases/deploy.sh save-images [--tag <sha>] [--out <dir>] [--skip-base]
#   bash releases/deploy.sh load-images [--dir <dir>]
#   bash releases/deploy.sh render <probe.yaml> <out-configmap.yaml>
#   bash releases/deploy.sh help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/deploy/k3s"
NS="nss-ndr"

log()  { echo -e "\033[1;32m[deploy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[deploy]\033[0m $*"; }
die()  { echo -e "\033[1;31m[deploy]\033[0m $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
NSS-NDR 探针统一部署脚本

用法:
  bash releases/deploy.sh install -i <网卡> [选项]
      -i, --interface <网卡>   抓包网卡（必填，如 enp5s0/eth1）
      -c, --config <文件>      probe 配置（默认 configs/probe.yaml，不存在则从示例复制）
      -t, --tag <镜像tag>      覆盖镜像版本（默认用 kustomization 当前 pin；须为 40 位 git sha）
      -p, --manager-port <端口> 管理后台 NodePort（默认 30603）
      --timeout <秒>            组件就绪等待超时（默认 1800）
      --images <dir>            本地离线镜像目录（默认 releases/images；存在则本地加载，不拉网络）
      --skip-checks            跳过环境预检

  bash releases/deploy.sh uninstall [-y] [--keep-images] [--keep-manifests]
  bash releases/deploy.sh save-images [--tag <sha>] [--out <dir>] [--skip-base]
  bash releases/deploy.sh load-images [--dir <dir>]
  bash releases/deploy.sh render <probe.yaml> <out-configmap.yaml>
  bash releases/deploy.sh help
EOF
  exit "${1:-0}"
}

# ============ install ============

# 生成部署凭据 deploy/k3s/25-secret.yaml（gitignored，不入库）
gen_secret() {
  local target="$DEPLOY_DIR/25-secret.yaml"
  if [[ -f "$target" ]]; then
    log "25-secret.yaml 已存在，跳过生成"
    return 0
  fi
  cat > "$target" <<EOF
# 自动生成（deploy.sh）；elastic 密码固定默认值，其余随机
apiVersion: v1
kind: Secret
metadata:
  name: nss-ndr-secrets
  namespace: nss-ndr
type: Opaque
stringData:
  elastic-password: "nss-ndr@2026"
  filebeat-password: $(openssl rand -hex 16)
  kibana-password: $(openssl rand -hex 16)
  kibana-encryption-key: $(openssl rand -hex 32)
  kibana-encrypted-saved-objects-key: $(openssl rand -hex 32)
  kibana-reporting-key: $(openssl rand -hex 32)
  xdr-push-password: $(openssl rand -hex 16)
  redis-password: $(openssl rand -hex 16)
EOF
  log "已生成 $target（elastic 登录：elastic / nss-ndr@2026）"
}

# 生成数据总线 TLS 证书 Secret（namespace 已存在时调用）
gen_certs() {
  local dir cnf
  dir=$(mktemp -d)
  cnf="$dir/openssl.cnf"
  cat > "$cnf" <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
[dn]
[ext]
subjectAltName = DNS:nss-logstash,DNS:nss-fleet-server,DNS:localhost,IP:127.0.0.1
EOF
  echo "== 生成 CA / 服务端 / 客户端证书 =="
  openssl genrsa -out "$dir/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -nodes -key "$dir/ca.key" -sha256 -days 3650 \
    -out "$dir/ca.crt" -subj "/CN=nss-ndr-ca"
  for srv in logstash fleet-server; do
    openssl genrsa -out "$dir/$srv.key" 2048 2>/dev/null
    openssl req -new -key "$dir/$srv.key" -out "$dir/$srv.csr" -subj "/CN=nss-$srv" -config "$cnf"
    openssl x509 -req -in "$dir/$srv.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
      -out "$dir/$srv.crt" -days 3650 -sha256 -extfile "$cnf" -extensions ext
  done
  openssl genrsa -out "$dir/elastic-agent.key" 2048 2>/dev/null
  openssl req -new -key "$dir/elastic-agent.key" -out "$dir/elastic-agent.csr" -subj "/CN=nss-elastic-agent"
  openssl x509 -req -in "$dir/elastic-agent.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -out "$dir/elastic-agent.crt" -days 3650 -sha256
  kubectl -n "$NS" create secret generic nss-ndr-certs \
    --from-file=ca.crt="$dir/ca.crt" \
    --from-file=logstash.crt="$dir/logstash.crt" \
    --from-file=logstash.key="$dir/logstash.key" \
    --from-file=elastic-agent.crt="$dir/elastic-agent.crt" \
    --from-file=elastic-agent.key="$dir/elastic-agent.key" \
    --from-file=fleet-server.crt="$dir/fleet-server.crt" \
    --from-file=fleet-server.key="$dir/fleet-server.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  rm -rf "$dir"
  log "证书 Secret nss-ndr-certs 已创建"
}

# 渲染 ConfigMap（内嵌 render-configs.py）
render_configmap() {
  local cfg="$1" out="$2"
  python3 - "$ROOT" "$cfg" "$out" <<'PYEOF'
import math, os, sys
try:
    import yaml
except ImportError:
    sys.exit("缺少 pyyaml，请先安装：pip3 install pyyaml")

root, cfg_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

TEMPLATES = {
    "suricata.yaml": "images/suricata/files/suricata.yaml",
    "threshold.conf": "images/suricata/files/threshold.conf",
    "local.zeek": "images/zeek/files/local.zeek",
    "node.cfg": "images/zeek/files/node.cfg",
    "zeekctl.cfg": "images/zeek/files/zeekctl.cfg",
    "networks.cfg": "images/zeek/files/networks.cfg",
}
STATIC_CONFIGS = {
    "kibana.yml": "images/kibana/kibana.yml",
    "config.zeek": "images/zeek/files/config.zeek",
    "strelka_backend.yaml": "images/strelka-backend/files/backend.yaml",
    "strelka_logging.yaml": "images/strelka-backend/files/logging.yaml",
    "strelka_passwords_dat": "images/strelka-backend/files/passwords.dat",
    "strelka_taste_yara": "images/strelka-backend/files/taste/taste.yara",
    "strelka_frontend.yaml": "images/strelka-manager/files/frontend.yaml",
    "strelka_filestream.yaml": "images/strelka-manager/files/filestream.yaml",
    "strelka_manager.yaml": "images/strelka-manager/files/manager.yaml",
}
POLICY_ROOT = "images/zeek/files/policy"

def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def render_templates(ctx):
    data = {}
    for key, rel in TEMPLATES.items():
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            content = f.read()
        for k, v in ctx.items():
            content = content.replace("${" + k + "}", v)
        data[key] = content
    return data

def render_policy():
    data = {}
    base = os.path.join(root, POLICY_ROOT)
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), base)
            top = rel.split(os.sep)[0]
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                data[f"policy_{top}_{rel[len(top)+1:].replace('/', '_')}"] = f.read()
    return data

def render_static():
    data = {}
    for key, rel in STATIC_CONFIGS.items():
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            data[key] = f.read()
    return data

cfg = load_cfg(cfg_path)
probe, suri, zeek = cfg["probe"], cfg["suricata"], cfg["zeek"]
pcap = suri.get("pcap", {})
if not probe.get("interface"):
    sys.exit("错误: probe.interface 未配置。镜像口是部署环境参数，请按服务器实际网卡填写（如 enp5s0）")
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
data = render_templates(ctx)
data.update(render_policy())
data.update(render_static())
data["bpf"] = probe.get("bpf", "")
data["all-rulesets.rules"] = ""
data["sensor_id"] = probe["id"]
data["interface"] = probe["interface"]
data["probe.yaml"] = open(cfg_path, encoding="utf-8").read()
cm = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "nss-ndr-config", "namespace": "nss-ndr"},
    "data": data,
}
with open(out_path, "w", encoding="utf-8") as f:
    yaml.safe_dump(cm, f, sort_keys=False, allow_unicode=True)
print(f"已生成 {out_path}（{len(data)} 个配置键）")
print(f"  接口={ctx['INTERFACE']} 线程={threads} pcap_max_files={max_files}")
PYEOF
}

# 本地离线镜像加载（k8s 拉取策略 IfNotPresent，本地已有则不再走网络）
load_local_images() {
  local dir="${1:-$ROOT/releases/images}"
  if [[ ! -d "$dir" ]]; then
    warn "镜像目录不存在，跳过本地加载: $dir"
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
  log "本地镜像加载完成（新加载 $loaded 个）✔"
}

cmd_install() {
  local interface="" config_file="" tag="" manager_port=30603 timeout=1800 images_dir="" skip_checks=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -i|--interface) interface="$2"; shift 2 ;;
      -c|--config) config_file="$2"; shift 2 ;;
      -t|--tag) tag="$2"; shift 2 ;;
      -p|--manager-port) manager_port="$2"; shift 2 ;;
      --timeout) timeout="$2"; shift 2 ;;
      --images) images_dir="$2"; shift 2 ;;
      --skip-checks) skip_checks=1; shift ;;
      -h|--help) usage 0 ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  [[ -n "$interface" ]] || die "缺少 -i/--interface（抓包网卡必填）"

  # 环境预检
  if [[ "$skip_checks" != "1" ]]; then
    log "环境预检..."
    command -v kubectl >/dev/null || die "缺少 kubectl"
    command -v openssl >/dev/null || die "缺少 openssl"
    command -v python3 >/dev/null || die "缺少 python3"
    python3 -c "import yaml" 2>/dev/null || die "缺少 python3 pyyaml 模块"
    kubectl get nodes >/dev/null 2>&1 || die "kubectl 无法访问集群"
    kubectl get nodes --no-headers 2>/dev/null | awk '$2 != "Ready" {exit 1}' || die "存在非 Ready 节点，请先恢复集群"
    log "节点可用资源: CPU=$(kubectl get nodes --no-headers -o custom-columns=:.status.allocatable.cpu 2>/dev/null | head -1) 内存=$(kubectl get nodes --no-headers -o custom-columns=:.status.allocatable.memory 2>/dev/null | head -1)"
  fi

  # probe 配置
  if [[ -z "$config_file" ]]; then
    config_file="$ROOT/configs/probe.yaml"
    if [[ ! -f "$config_file" ]]; then
      cp "$ROOT/configs/probe.yaml.example" "$config_file"
      warn "已从示例创建 configs/probe.yaml，请填写实际参数后重试"
    fi
  fi
  [[ -f "$config_file" ]] || die "配置文件不存在: $config_file"
  local tmp_cfg=""
  if [[ -n "$interface" ]]; then
    tmp_cfg=$(mktemp)
    sed "s/^\(\s*interface:\s*\).*/\1$interface/" "$config_file" > "$tmp_cfg"
    config_file="$tmp_cfg"
    log "镜像口: $interface"
  fi

  # 镜像 tag（覆盖 kustomization pin，须为 40 位 sha）
  if [[ -n "$tag" ]]; then
    [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || die "镜像 tag 应为 40 位 git sha（当前: $tag）"
    sed -i.bak "s/\(newTag: \).*/\1$tag/" "$DEPLOY_DIR/kustomization.yaml"
    rm -f "$DEPLOY_DIR/kustomization.yaml.bak"
    log "镜像 tag 覆盖为: $tag"
  fi

  # 本地离线镜像优先加载
  load_local_images "${images_dir:-$ROOT/releases/images}"

  # 渲染 ConfigMap
  log "渲染 ConfigMap..."
  render_configmap "$config_file" "$DEPLOY_DIR/10-configmap.yaml"
  [[ -n "$tmp_cfg" ]] && rm -f "$tmp_cfg"

  # 凭据与证书
  log "准备凭据..."
  gen_secret
  log "创建命名空间..."
  kubectl create ns "$NS" --dry-run=client -o yaml 2>/dev/null | kubectl apply -f - >/dev/null
  if ! kubectl get secret nss-ndr-certs -n "$NS" >/dev/null 2>&1; then
    gen_certs
  else
    log "证书 Secret 已存在，跳过"
  fi

  # fleet-init Job 不可变，重复部署先删旧 Job
  kubectl delete job nss-fleet-init -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -k "$DEPLOY_DIR"
  log "资源已应用，等待组件就绪（超时 ${timeout}s）..."

  local deadline=$((SECONDS + timeout))
  while [[ $SECONDS -lt $deadline ]]; do
    if ! kubectl get pods -n "$NS" --no-headers 2>/dev/null |
        awk '$3 != "Running" && $3 != "Completed" {n++} END {exit n}'; then
      log "全部组件就绪 ✔"
      break
    fi
    sleep 15
  done
  if kubectl get pods -n "$NS" --no-headers 2>/dev/null |
      awk '$3 != "Running" && $3 != "Completed" {n++} END {exit n}'; then
    warn "部分组件未在超时时间内就绪："
    kubectl get pods -n "$NS" | awk '$3 != "Running" && $3 != "Completed"'
    die "部署超时，请检查上述组件日志"
  fi

  log "================ 部署完成 ================"
  echo ""
  echo "  探针管理后台 : http://<本机IP>:$manager_port   （初始账号 admin / admin，登录后请改密）"
  echo "  Kibana       : http://<本机IP>:30601/kibana   （elastic / nss-ndr@2026）"
  echo "  NDR 看板     : 已内嵌于管理后台“可视化分析”菜单"
  echo "  镜像口       : $interface"
  echo "  探针 ID      : $(python3 -c "import yaml,sys; print(yaml.safe_load(open('$DEPLOY_DIR/10-configmap.yaml'))['data'].get('sensor_id',''))" 2>/dev/null)"
  echo ""
  echo "=========================================="
}

# ============ uninstall ============
cmd_uninstall() {
  local assume_yes=0 keep_images=0 keep_manifests=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes) assume_yes=1; shift ;;
      --keep-images) keep_images=1; shift ;;
      --keep-manifests) keep_manifests=1; shift ;;
      -h|--help) usage 0 ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  if [[ "$assume_yes" != "1" ]]; then
    echo "本操作将删除命名空间 $NS（含全部项目组件与数据卷）以及项目镜像/目录。"
    read -r -p "确认继续? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "已取消"; exit 0; }
  fi
  command -v kubectl >/dev/null || die "缺少 kubectl"

  if kubectl get ns "$NS" >/dev/null 2>&1; then
    log "删除命名空间 $NS..."
    kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
    local deadline=$((SECONDS + 120))
    while [[ $SECONDS -lt $deadline ]]; do
      kubectl get ns "$NS" >/dev/null 2>&1 || { log "命名空间已删除 ✔"; break; }
      sleep 5
    done
    if kubectl get ns "$NS" >/dev/null 2>&1; then
      warn "命名空间 Terminating 超时，强制清理残留 pod..."
      kubectl delete pod -n "$NS" --all --force --grace-period=0 >/dev/null 2>&1 || true
      sleep 15
    fi
  else
    log "命名空间不存在，跳过"
  fi

  log "清理残留容器..."
  for c in $(crictl ps -a -q --label "io.kubernetes.pod.namespace=$NS" 2>/dev/null); do
    crictl stop -t 2 "$c" >/dev/null 2>&1 || true
    crictl rm -f "$c" >/dev/null 2>&1 || true
  done

  if [[ "$keep_images" != "1" ]]; then
    log "清理项目镜像..."
    ctr -n k8s.io images ls 2>/dev/null | grep "ghcr.io/cxiyuan/nss-ndr/" | awk '{print $1}' | sort -u |
      while read -r img; do ctr -n k8s.io images rm "$img" >/dev/null 2>&1 || true; done
    for prefix in \
      docker.elastic.co/elasticsearch/elasticsearch \
      docker.io/library/redis \
      docker.io/library/busybox; do
      ctr -n k8s.io images ls 2>/dev/null | awk '{print $1}' | sort -u |
        grep "^$prefix" | while read -r img; do
          ctr -n k8s.io images rm "$img" >/dev/null 2>&1 || true
        done
    done
    crictl images 2>/dev/null | awk '$1=="<none>" {print $3}' | while read -r id; do
      crictl rmi "$id" >/dev/null 2>&1 || true
    done
    log "镜像清理完成 ✔"
  fi

  if [[ "$keep_manifests" != "1" ]]; then
    for d in /opt/nss-deploy /opt/so; do
      if [[ -d "$d" ]]; then
        warn "移除 $d"
        rm -rf "$d"
      fi
    done
  fi

  log "验证残留..."
  echo "  namespace: $(kubectl get ns "$NS" 2>&1 | tail -1)"
  echo "  项目镜像: $(ctr -n k8s.io images ls 2>/dev/null | grep -c 'ghcr.io/cxiyuan/nss-ndr/' || true) 个"
  log "卸载完成 ✔（其他业务未受影响）"
}

# ============ save-images / load-images ============
cmd_save_images() {
  local tag="" out="" include_base=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag) tag="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      --skip-base) include_base=0; shift ;;
      -h|--help) usage 0 ;;
      *) echo "未知参数: $1"; usage 1 ;;
    esac
  done
  command -v skopeo >/dev/null || die "缺少 skopeo（brew install skopeo / apt install skopeo）"
  if [[ -z "$tag" ]]; then
    tag=$(grep -m1 "newTag:" "$DEPLOY_DIR/kustomization.yaml" | awk '{print $2}')
  fi
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] || die "镜像 tag 无效: $tag"
  out="${out:-$ROOT/releases/images}"
  mkdir -p "$out"

  local project_images=()
  while IFS= read -r img; do
    project_images+=("$img")
  done < <(grep "name: ghcr.io/cxiyuan/nss-ndr" "$DEPLOY_DIR/kustomization.yaml" | sed 's/.*name: //' | sort -u)
  local base_images=(
    "docker.elastic.co/elasticsearch/elasticsearch:9.3.3"
    "docker.io/library/redis:7-alpine"
    "docker.io/library/busybox:1.36"
  )

  save_one() {
    local src="$1" out_file="$2"
    if [[ -f "$out_file" && -s "$out_file" ]]; then
      echo "已存在，跳过: $(basename "$out_file")"
      return 0
    fi
    echo "导出: $src -> $(basename "$out_file")"
    skopeo copy --retry-times=3 \
      --override-os linux --override-arch amd64 \
      "docker://$src" "docker-archive:$out_file:$src"
  }

  local total=0 img name b
  for img in "${project_images[@]}"; do
    name=$(basename "$img")
    save_one "${img}:${tag}" "$out/${name}-${tag:0:12}.tar"
    total=$((total+1))
  done
  if [[ "$include_base" == "1" ]]; then
    for b in "${base_images[@]}"; do
      name=$(echo "$b" | tr '/:' '__')
      save_one "$b" "$out/${name}.tar"
      total=$((total+1))
    done
  fi
  {
    echo "# NSS-NDR 离线镜像包（tag=$tag，生成时间 $(date -u +%Y-%m-%dT%H:%M:%SZ)）"
    for img in "${project_images[@]}"; do
      echo "${img}:${tag}"
    done
    if [[ "$include_base" == "1" ]]; then
      for b in "${base_images[@]}"; do
        echo "$b"
      done
    fi
  } > "$out/manifest.txt"
  echo ""
  echo "完成：共 $total 个镜像已导出到 $out"
}

cmd_load_images() {
  local dir="$ROOT/releases/images"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      *) dir="$1"; shift ;;
    esac
  done
  load_local_images "$dir"
}

# ============ 入口 ============
cmd="${1:-help}"
shift 2>/dev/null || true
case "$cmd" in
  install) cmd_install "$@" ;;
  uninstall) cmd_uninstall "$@" ;;
  save-images) cmd_save_images "$@" ;;
  load-images) cmd_load_images "$@" ;;
  render) [[ $# -eq 2 ]] || { echo "用法: deploy.sh render <probe.yaml> <out.yaml>"; exit 1; }
          render_configmap "$1" "$2" ;;
  help|-h|--help|"") usage 0 ;;
  *) echo "未知命令: $cmd"; usage 1 ;;
esac
