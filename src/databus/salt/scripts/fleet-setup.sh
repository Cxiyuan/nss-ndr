#!/usr/bin/env bash
# ============================================================
# 数据总线 Fleet 初始化（Salt fleet-setup.sls 调用）
#
# 幂等执行：
#   1. 创建 Fleet default output（指向 elasticsearch:9200）
#   2. 创建 agent policies（fleet-server-policy / nss-ndr-zeek-policy）
#   3. 创建 enrollment API keys，写回 /etc/nss-ndr/.env
#   4. 创建 Zeek Integration package policy
#      - 新部署：直接建 43 streams 全启用
#      - 已部署（如旧版只有 5 streams）：通过 NSS_ZEEK_POLICY_FORCE_RECREATE=1
#        或带 --force 参数删除旧的 nss-ndr-zeek-1.0.0 后重建为 43 streams
#
# 依赖：ES + Kibana 已 healthy，KIBANA_SERVICE_TOKEN 已写入 .env
# 用法：/opt/nss-ndr/scripts/fleet-setup.sh [--force]
# ============================================================
set -euo pipefail

FORCE_RECREATE="false"
if [[ "${1:-}" == "--force" || "${NSS_ZEEK_POLICY_FORCE_RECREATE:-0}" == "1" ]]; then
  FORCE_RECREATE="true"
fi

ENV_FILE="${NSS_ENV_FILE:-/etc/nss-ndr/.env}"
# 脚本在 salt-minion 容器内执行（nss-net），用 DNS 名访问 ES / Kibana
ES_URL="${NSS_ES_URL:-http://elasticsearch:9200}"
KIBANA_URL="${NSS_KIBANA_URL:-http://kibana:5601}"

SUPER_USER="elastic"
SUPER_PASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
ZEEK_POLICY="nss-ndr-zeek-policy"
FLEET_POLICY="fleet-server-policy"

log() { echo -e "\n===== $1 ====="; }

write_kv() {
  local KEY="$1" VAL="$2"
  # 幂等：值未变化且 .env 只读时跳过写入（容器内 .env 挂载 ro，重复执行不报错）
  local CURRENT
  CURRENT=$(grep "^$KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | head -1 || true)
  if [[ "$CURRENT" == "$VAL" ]]; then
    echo "  ✓ $KEY 已是最新（跳过写入）"
    return 0
  fi
  if grep -q "^$KEY=" "$ENV_FILE"; then
    python3 - << PYEOF
import re
key = "$KEY"; val = "$VAL"; path = "$ENV_FILE"
content = open(path).read()
content = re.sub(r'^'+key+r'=.*$', f'{key}={val}', content, count=1, flags=re.MULTILINE)
open(path, 'w').write(content)
PYEOF
  else
    echo "$KEY=$VAL" >> "$ENV_FILE"
  fi
  echo "  ✓ $KEY 已更新"
}

kibana_req() {
  local method="$1" path="$2" data="${3:-}"
  if [[ -n "$data" ]]; then
    curl -fsS -u "$SUPER_USER:$SUPER_PASS" -X "$method" "$KIBANA_URL$path" \
      -H "Content-Type: application/json" -H "kbn-xsrf: true" -d "$data"
  else
    curl -fsS -u "$SUPER_USER:$SUPER_PASS" -X "$method" "$KIBANA_URL$path" \
      -H "Content-Type: application/json" -H "kbn-xsrf: true"
  fi
}



# 1) Fleet default output（幂等 + 修正 hosts）
# 注意：Kibana 首次启用 Fleet 时会自动预置 default output（hosts=localhost:9200），
#       必须显式修正为 elasticsearch:9200，否则 agent/fleet-server 会连不上 ES。
log "1) 创建 Fleet default output"
OUTPUTS=$(kibana_req GET "/api/fleet/outputs")
if echo "$OUTPUTS" | grep -q '"is_default":true'; then
  OUTPUT_ID=$(echo "$OUTPUTS" | python3 -c "
import sys, json
for o in json.load(sys.stdin).get('items', []):
    if o.get('is_default'):
        print(o['id']); break
")
  kibana_req PUT "/api/fleet/outputs/$OUTPUT_ID" '{
    "name": "default",
    "type": "elasticsearch",
    "hosts": ["http://elasticsearch:9200"],
    "is_default": true,
    "is_default_monitoring": true
  }' >/dev/null
  echo "  ✓ default output hosts 已修正为 elasticsearch:9200"
else
  kibana_req POST "/api/fleet/outputs" '{
    "name": "default",
    "type": "elasticsearch",
    "hosts": ["http://elasticsearch:9200"],
    "is_default": true,
    "is_default_monitoring": true
  }' >/dev/null
  echo "  ✓ default output 已创建"
fi

# 2) agent policies（幂等）
log "2) 创建 agent policies"
if ! kibana_req GET "/api/fleet/agent_policies/$FLEET_POLICY" >/dev/null 2>&1; then
  kibana_req POST "/api/fleet/agent_policies" '{
    "id": "fleet-server-policy",
    "name": "Fleet Server policy",
    "namespace": "default",
    "monitoring_enabled": ["logs", "metrics"],
    "has_fleet_server": true
  }' >/dev/null
  echo "  ✓ fleet-server-policy 已创建"
fi
if ! kibana_req GET "/api/fleet/agent_policies/$ZEEK_POLICY" >/dev/null 2>&1; then
  kibana_req POST "/api/fleet/agent_policies" '{
    "id": "nss-ndr-zeek-policy",
    "name": "NSS-NDR Zeek Agent Policy",
    "namespace": "default",
    "monitoring_enabled": ["logs", "metrics"]
  }' >/dev/null
  echo "  ✓ nss-ndr-zeek-policy 已创建"
fi


# 3) enrollment API keys（幂等）
log "3) 创建 enrollment API keys"
create_enroll_key() {
  local name="$1" policy_id="$2"
  local existing
  existing=$(kibana_req GET "/api/fleet/enrollment_api_keys" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in d.get('items', []):
    if k.get('policy_id') == '$policy_id':
        print(k.get('api_key', ''))
        break
")
  if [[ -n "$existing" ]]; then
    echo "$existing"
    return
  fi
  kibana_req POST "/api/fleet/enrollment_api_keys" "{\"name\": \"$name\", \"policy_id\": \"$policy_id\", \"expiration\": \"30d\"}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['item']['api_key'])"
}

FLEET_KEY=$(create_enroll_key "nss-ndr-fleet-server-key" "$FLEET_POLICY")
write_kv "FLEET_ENROLLMENT_TOKEN" "$FLEET_KEY"
AGENT_KEY=$(create_enroll_key "nss-ndr-zeek-agent-key" "$ZEEK_POLICY")
write_kv "ELASTIC_AGENT_ENROLLMENT_TOKEN" "$AGENT_KEY"

# 4) Zeek Integration package policy（幂等）
# 启用 Zeek Integration 5.0.1 全部 43 个 dataset（与 manifest.yml 一致）。
# 每个 stream 的 filenames / tags 取自 images/zeek-integration/zeek-5.0.1/data_stream/<ds>/manifest.yml
# 的 vars.filenames.default / vars.tags.default —— 不要再手工挑选，否则会漏。
# 升级路径：旧版只配 5 streams 的部署，带 --force（或 NSS_ZEEK_POLICY_FORCE_RECREATE=1）
#           会先删除旧的 nss-ndr-zeek-1.0.0，再重建为 43 streams。
log "4) 创建 Zeek Integration package policy（43 个 dataset）"
if [[ "$FORCE_RECREATE" == "true" ]]; then
  OLD_ID=$(kibana_req GET "/api/fleet/package_policies" | python3 -c "
import sys, json
for p in json.load(sys.stdin).get('items', []):
  if p.get('name') == 'nss-ndr-zeek-1.0.0':
    print(p.get('id')); break
" 2>/dev/null || true)
  if [[ -n "$OLD_ID" ]]; then
    kibana_req DELETE "/api/fleet/package_policies/$OLD_ID?force=true" >/dev/null 2>&1 || true
    echo "  ✓ 旧的 nss-ndr-zeek-1.0.0 ($OLD_ID) 已删除（--force）"
  fi
fi
if ! kibana_req GET "/api/fleet/package_policies" | grep -q '"name":"nss-ndr-zeek-1.0.0"'; then
  kibana_req POST "/api/fleet/package_policies" '{
    "name": "nss-ndr-zeek-1.0.0",
    "description": "NSS-NDR Zeek Integration (43 datasets, full coverage)",
    "namespace": "default",
    "policy_id": "nss-ndr-zeek-policy",
    "package": {"name": "zeek", "version": "5.0.1"},
    "inputs": [{
      "type": "logfile",
      "policy_template": "zeek",
      "enabled": true,
      "vars": {"base_paths": {"type": "text", "value": ["/var/log/zeek"]}},
      "streams": [
        {"id": "nss-ndr-zeek-capture-loss", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.capture_loss"}, "vars": {"filenames": {"type": "text", "value": ["capture_loss.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-capture-loss"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-connection", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.connection"}, "vars": {"filenames": {"type": "text", "value": ["conn.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-connection"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dce-rpc", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dce_rpc"}, "vars": {"filenames": {"type": "text", "value": ["dce_rpc.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dce-rpc"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dhcp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dhcp"}, "vars": {"filenames": {"type": "text", "value": ["dhcp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dhcp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dnp3", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dnp3"}, "vars": {"filenames": {"type": "text", "value": ["dnp3.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dnp3"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dns", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dns"}, "vars": {"filenames": {"type": "text", "value": ["dns.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dns"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dpd", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dpd"}, "vars": {"filenames": {"type": "text", "value": ["dpd.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dpd"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-files", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.files"}, "vars": {"filenames": {"type": "text", "value": ["files.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-files"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ftp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ftp"}, "vars": {"filenames": {"type": "text", "value": ["ftp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ftp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-http", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.http"}, "vars": {"filenames": {"type": "text", "value": ["http.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-http"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-intel", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.intel"}, "vars": {"filenames": {"type": "text", "value": ["intel.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-intel"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-irc", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.irc"}, "vars": {"filenames": {"type": "text", "value": ["irc.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-irc"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-kerberos", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.kerberos"}, "vars": {"filenames": {"type": "text", "value": ["kerberos.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-kerberos"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-known-certs", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.known_certs"}, "vars": {"filenames": {"type": "text", "value": ["known_certs.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-known_certs"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-known-hosts", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.known_hosts"}, "vars": {"filenames": {"type": "text", "value": ["known_hosts.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-known_hosts"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-known-services", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.known_services"}, "vars": {"filenames": {"type": "text", "value": ["known_services.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-known_services"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-modbus", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.modbus"}, "vars": {"filenames": {"type": "text", "value": ["modbus.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-modbus"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-mysql", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.mysql"}, "vars": {"filenames": {"type": "text", "value": ["mysql.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-mysql"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-notice", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.notice"}, "vars": {"filenames": {"type": "text", "value": ["notice.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-notice"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ntlm", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ntlm"}, "vars": {"filenames": {"type": "text", "value": ["ntlm.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ntlm"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ntp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ntp"}, "vars": {"filenames": {"type": "text", "value": ["ntp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ntp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ocsp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ocsp"}, "vars": {"filenames": {"type": "text", "value": ["ocsp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ocsp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-pe", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.pe"}, "vars": {"filenames": {"type": "text", "value": ["pe.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-pe"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-radius", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.radius"}, "vars": {"filenames": {"type": "text", "value": ["radius.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-radius"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-rdp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.rdp"}, "vars": {"filenames": {"type": "text", "value": ["rdp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-rdp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-rfb", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.rfb"}, "vars": {"filenames": {"type": "text", "value": ["rfb.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-rfb"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-signature", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.signature"}, "vars": {"filenames": {"type": "text", "value": ["signature.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-signature"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-sip", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.sip"}, "vars": {"filenames": {"type": "text", "value": ["sip.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-sip"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-smb-cmd", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.smb_cmd"}, "vars": {"filenames": {"type": "text", "value": ["smb_cmd.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-smb-cmd"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-smb-files", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.smb_files"}, "vars": {"filenames": {"type": "text", "value": ["smb_files.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-smb-files"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-smb-mapping", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.smb_mapping"}, "vars": {"filenames": {"type": "text", "value": ["smb_mapping.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek.smb_mapping"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-smtp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.smtp"}, "vars": {"filenames": {"type": "text", "value": ["smtp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-smtp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-snmp", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.snmp"}, "vars": {"filenames": {"type": "text", "value": ["snmp.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-snmp"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-socks", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.socks"}, "vars": {"filenames": {"type": "text", "value": ["socks.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-socks"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-software", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.software"}, "vars": {"filenames": {"type": "text", "value": ["software.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-software"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ssh", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ssh"}, "vars": {"filenames": {"type": "text", "value": ["ssh.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ssh"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ssl", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ssl"}, "vars": {"filenames": {"type": "text", "value": ["ssl.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ssl"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-stats", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.stats"}, "vars": {"filenames": {"type": "text", "value": ["stats.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-stats"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-syslog", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.syslog"}, "vars": {"filenames": {"type": "text", "value": ["syslog.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-syslog"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-traceroute", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.traceroute"}, "vars": {"filenames": {"type": "text", "value": ["traceroute.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-traceroute"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-tunnel", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.tunnel"}, "vars": {"filenames": {"type": "text", "value": ["tunnel.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-tunnel"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-weird", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.weird"}, "vars": {"filenames": {"type": "text", "value": ["weird.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-weird"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-x509", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.x509"}, "vars": {"filenames": {"type": "text", "value": ["x509.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-x509"]}, "preserve_original_event": {"type": "bool", "value": false}}}
      ]
    }]
  }' >/dev/null
  echo "  ✓ Zeek Integration package policy 已创建（43 streams 全启用）"
else
  # 检查现有 policy 的 stream 数，若 <43 提示用户用 --force 升级
  STREAM_COUNT=$(kibana_req GET "/api/fleet/package_policies" | python3 -c "
import sys, json
for p in json.load(sys.stdin).get('items', []):
  if p.get('name') == 'nss-ndr-zeek-1.0.0':
    for i in p.get('inputs', []):
      print(len(i.get('streams', [])))
    break
" 2>/dev/null || echo 0)
  if [[ "$STREAM_COUNT" -lt 43 ]]; then
    echo "  ⚠ Zeek Integration package policy 已存在但只有 $STREAM_COUNT streams（<43）"
    echo "    升级方式: /opt/nss-ndr/scripts/fleet-setup.sh --force"
  else
    echo "  ✓ Zeek Integration package policy 已存在（43 streams）"
  fi
fi

log "完成 ✓ Fleet 初始化完成（output/policy/enrollment keys/Zeek Integration）"
