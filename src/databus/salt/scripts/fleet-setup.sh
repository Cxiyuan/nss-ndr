#!/usr/bin/env bash
# ============================================================
# 数据总线 Fleet 初始化（Salt fleet-setup.sls 调用）
#
# 幂等执行：
#   1. 创建 Fleet default output（指向 elasticsearch:9200）
#   2. 创建 agent policies（fleet-server-policy / nss-ndr-zeek-policy）
#   3. 创建 enrollment API keys，写回 /etc/nss-ndr/.env
#   4. 创建 Zeek Integration package policy
#
# 依赖：ES + Kibana 已 healthy，KIBANA_SERVICE_TOKEN 已写入 .env
# 用法：/opt/nss-ndr/scripts/fleet-setup.sh
# ============================================================
set -euo pipefail

ENV_FILE="${NSS_ENV_FILE:-/etc/nss-ndr/.env}"
ES_URL="http://localhost:9200"
KIBANA_URL="http://localhost:5601"

SUPER_USER="elastic"
SUPER_PASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
ZEEK_POLICY="nss-ndr-zeek-policy"
FLEET_POLICY="fleet-server-policy"

log() { echo -e "\n===== $1 ====="; }

write_kv() {
  local KEY="$1" VAL="$2"
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
log "4) 创建 Zeek Integration package policy"
if ! kibana_req GET "/api/fleet/package_policies" | grep -q '"name":"nss-ndr-zeek-1.0.0"'; then
  kibana_req POST "/api/fleet/package_policies" '{
    "name": "nss-ndr-zeek-1.0.0",
    "description": "NSS-NDR Zeek Integration",
    "namespace": "default",
    "policy_id": "nss-ndr-zeek-policy",
    "package": {"name": "zeek", "version": "5.0.1"},
    "inputs": [{
      "type": "logfile",
      "policy_template": "zeek",
      "enabled": true,
      "vars": {"base_paths": {"type": "text", "value": ["/var/log/zeek"]}},
      "streams": [
        {"id": "nss-ndr-zeek-conn", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.connection"},
         "vars": {"filenames": {"type": "text", "value": ["conn.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-connection"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-http", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.http"},
         "vars": {"filenames": {"type": "text", "value": ["http.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-http"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-dns", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.dns"},
         "vars": {"filenames": {"type": "text", "value": ["dns.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-dns"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-ssl", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.ssl"},
         "vars": {"filenames": {"type": "text", "value": ["ssl.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-ssl"]}, "preserve_original_event": {"type": "bool", "value": false}}},
        {"id": "nss-ndr-zeek-notice", "enabled": true, "data_stream": {"type": "logs", "dataset": "zeek.notice"},
         "vars": {"filenames": {"type": "text", "value": ["notice.log"]}, "tags": {"type": "text", "value": ["forwarded", "zeek-notice"]}, "preserve_original_event": {"type": "bool", "value": false}}}
      ]
    }]
  }' >/dev/null
  echo "  ✓ Zeek Integration package policy 已创建"
else
  echo "  Zeek Integration package policy 已存在"
fi

log "完成 ✓ Fleet 初始化完成（output/policy/enrollment keys/Zeek Integration）"
