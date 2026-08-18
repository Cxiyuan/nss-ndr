#!/usr/bin/env bash
# NSS-NDR 验证测试流量生成脚本
#
# 用途：在探针镜像网段内的任意主机上运行，生成扫描 / Web 攻击 / DNS 异常 / SMB / TLS
#       等验证流量，用于端到端验证检测链路：
#         检测线索（Suricata）-> 网络元数据确认（Zeek）-> 线索推送 XDR -> XDR 下发分析任务
#         -> ndr-agent（LLM）调 mcp-server 工具集给出结论
#
# 注意：NDR 不内置可视化（划归 XDR 平台）；本脚本只产生攻击流量，不针对任何可视化组件做探测。
# 依赖：系统自带工具（curl / nc / dig / python3 / smbutil），无需额外安装
#
# 用法:
#   bash test/traffic-test.sh                          # 全部流量，目标默认本机所在网段网关
#   bash test/traffic-test.sh 10.44.77.250             # 指定目标 IP
#   bash test/traffic-test.sh --scan --web 10.44.77.250
#   bash test/traffic-test.sh --target 10.44.77.250 --dns-server 10.44.77.254 --skip-smb
#
# 选项:
#   --scan          内网端口扫描（TCP connect 探测常见端口）
#   --web           Web 攻击（SQL 注入 / 路径穿越 / 命令注入 / 扫描器 UA）
#   --dns           DNS 异常（长域名查询 / TXT 隧道特征）
#   --smb           SMB 会话（探测 445 并尝试列共享，需目标开放 SMB）
#   --tls           TLS 握手（生成加密流量与 JA3 指纹）
#   --target <IP>   目标主机（默认：自动探测本网段网关）
#   --dns-server <IP> DNS 服务器（默认跟随系统 DNS）
#   --skip-<x>      跳过对应流量（如 --skip-smb）
#   -h, --help      帮助
set -uo pipefail

log()  { echo -e "\033[1;36m[traffic-test]\033[0m $*"; }
warn() { echo -e "\033[1;33m[traffic-test]\033[0m $*"; }
die()  { echo -e "\033[1;31m[traffic-test]\033[0m $*" >&2; exit 1; }

# ---------- 参数 ----------
TARGET=""
DNS_SERVER=""
DO_SCAN=1
DO_WEB=1
DO_DNS=1
DO_SMB=1
DO_TLS=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan) DO_SCAN=1; shift ;;
    --web) DO_WEB=1; shift ;;
    --dns) DO_DNS=1; shift ;;
    --smb) DO_SMB=1; shift ;;
    --tls) DO_TLS=1; shift ;;
    --skip-scan) DO_SCAN=0; shift ;;
    --skip-web) DO_WEB=0; shift ;;
    --skip-dns) DO_DNS=0; shift ;;
    --skip-smb) DO_SMB=0; shift ;;
    --skip-tls) DO_TLS=0; shift ;;
    --target) TARGET="$2"; shift 2 ;;
    --dns-server) DNS_SERVER="$2"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//' | head -31; exit 0 ;;
    -*)
      # 首参数若是 IP 视为目标（兼容 bash test/traffic-test.sh 10.44.77.250）
      if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ -z "$TARGET" ]]; then
        TARGET="$1"; shift
      else
        echo "未知参数: $1"; exit 1
      fi
      ;;
    *)
      if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ -z "$TARGET" ]]; then
        TARGET="$1"; shift
      else
        echo "未知参数: $1"; exit 1
      fi
      ;;
  esac
done

# ---------- 目标探测 ----------
if [[ -z "$TARGET" ]]; then
  # 自动取本机网关作为默认目标（镜像网段内流量通常可被探针捕获）
  TARGET=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
  [[ -z "$TARGET" ]] && TARGET=$(route -n get default 2>/dev/null | awk '/gateway/ {print $2; exit}')
fi
[[ -z "$TARGET" ]] && die "无法自动确定目标，请用 --target <IP> 指定"
log "目标主机: $TARGET"

# ---------- 1. 内网扫描 ----------
scan_sim() {
  log "== 内网扫描模拟（目标 $TARGET）=="
  command -v python3 >/dev/null || { warn "缺少 python3，跳过扫描"; return; }
  python3 - "$TARGET" <<'EOF'
import socket, sys
target = sys.argv[1]
ports = [22, 80, 443, 445, 3389, 3306, 5432, 6379, 8080, 9200, 30603, 8081]
open_ports = []
for p in ports:
    s = socket.socket()
    s.settimeout(0.5)
    try:
        if s.connect_ex((target, p)) == 0:
            open_ports.append(p)
    except Exception:
        pass
    finally:
        s.close()
print("  TCP 探测 12 个常见端口，开放:", open_ports)
EOF
  # 额外对网段内邻近 IP 做轻量探测（触发扫描线索）
  local base
  base=$(echo "$TARGET" | awk -F. '{print $1"."$2"."$3}')
  for host in 1 2 250 254; do
    for p in 22 445; do
      nc -z -w 1 "$base.$host" "$p" >/dev/null 2>&1 && echo "  $base.$host:$p 开放" || true
    done
  done
}

# ---------- 2. Web 攻击 ----------
web_sim() {
  log "== Web 攻击模拟（目标 $TARGET）=="
  command -v curl >/dev/null || { warn "缺少 curl，跳过 Web 攻击"; return; }
  local urls=(
    "http://$TARGET:30603/api/health?id=1%27%20OR%20%271%27=%271"
    "http://$TARGET:30603/../../../../etc/passwd"
    "http://$TARGET:30603/api/health?cmd=cat%20/etc/passwd"
    # NDR 不提供 Kibana/可视化；XDR 平台才是数据分析界面。本脚本仅产生攻击流量，
    # 不针对任何具体可视化组件做探测；如下游 XDR 提供自身健康端点可在此追加。
  )
  for u in "${urls[@]}"; do
    curl -s -o /dev/null -m 5 -w "  %{http_code}  $u\n" "$u" || true
  done
  # 扫描器 UA（sqlmap / nikto / nuclei 特征）
  for ua in "sqlmap/1.7.2#stable" "nikto/2.5.0" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"; do
    curl -s -o /dev/null -m 5 -A "$ua" -w "  UA[$ua] -> %{http_code}\n" "http://$TARGET:30603/api/health" || true
  done
}

# ---------- 3. DNS 异常 ----------
dns_sim() {
  log "== DNS 异常模拟（服务器 ${DNS_SERVER:-系统默认}）=="
  command -v dig >/dev/null || { warn "缺少 dig，跳过 DNS"; return; }
  local long_name tunnel_name
  long_name=$(python3 -c "print('a'*60 + '.dns-test.invalid')" 2>/dev/null || printf 'a%.0s' {1..60})
  tunnel_name="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.tunnel-txt.invalid"
  if [[ -n "$DNS_SERVER" ]]; then
    dig +time=2 +tries=1 "@$DNS_SERVER" "$long_name" >/dev/null 2>&1 || true
    dig +time=2 +tries=1 "@$DNS_SERVER" -t TXT "$tunnel_name" >/dev/null 2>&1 || true
  else
    dig +time=2 +tries=1 "$long_name" >/dev/null 2>&1 || true
    dig +time=2 +tries=1 -t TXT "$tunnel_name" >/dev/null 2>&1 || true
  fi
  echo "  已发送长域名查询与 TXT 隧道特征查询"
}

# ---------- 4. SMB 会话 ----------
smb_sim() {
  log "== SMB 会话模拟（目标 $TARGET:445）=="
  nc -z -w 2 "$TARGET" 445 >/dev/null 2>&1 || { warn "目标 445 未开放，跳过 SMB（探针镜像口有 SMB 流量时才有 zeek.smb 元数据）"; return; }
  if command -v smbutil >/dev/null 2>&1; then
    smbutil view -N "//$TARGET" 2>&1 | head -6 || true
  elif command -v smbclient >/dev/null 2>&1; then
    smbclient -N -L "//$TARGET" 2>&1 | head -6 || true
  else
    warn "无 smbutil/smbclient，仅产生 TCP 445 连接"
    nc -z -w 2 "$TARGET" 445 || true
  fi
}

# ---------- 5. TLS 握手 ----------
tls_sim() {
  log "== TLS 握手模拟（目标 $TARGET）=="
  command -v curl >/dev/null || { warn "缺少 curl，跳过 TLS"; return; }
  # 443 为常见 HTTPS；8081 为本探针 ndr-agent 端口（XDR 下发的研判任务会落到这里，便于产生 TLS 元数据）
  for port in 443 8081; do
    curl -sk -o /dev/null -m 5 -w "  https://$TARGET:$port -> %{http_code} (TLS %{ssl_verify_result})\n" \
      "https://$TARGET:$port/" 2>/dev/null || echo "  https://$TARGET:$port 无响应" || true
  done
}

# ---------- 执行 ----------
[[ "$DO_SCAN" == "1" ]] && scan_sim
[[ "$DO_WEB" == "1" ]] && web_sim
[[ "$DO_DNS" == "1" ]] && dns_sim
[[ "$DO_SMB" == "1" ]] && smb_sim
[[ "$DO_TLS" == "1" ]] && tls_sim

log "================ 测试流量生成完成 ================"
echo ""
echo "  验证方式（在部署机）:"
echo "    1) 检查检测线索（ES 直查）: docker exec nss-elasticsearch curl -s -u xdr-push:\$XDR_PASSWORD http://localhost:9200/logs-suricata.alerts-so/_count | head -c 200"
echo "    2) 检查网络元数据: curl -s http://localhost:30603/api/etopen/tree | head"
echo "    3) XDR 分析任务: POST /api/xdr/task（Bearer 令牌）由 NDR 在本地元数据上执行关联分析"
echo "    4) XDR 研判任务: POST /api/xdr/agent/task → ndr-agent（LLM）→ mcp-server → ES，给出结论+证据链"
echo ""
