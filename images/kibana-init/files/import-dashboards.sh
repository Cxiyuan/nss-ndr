#!/bin/sh
# 等待 Kibana 就绪后导入 NDR 看板（saved objects _import，overwrite=true）
# 失败重试；成功一次后常驻（后续若看板丢失需手动重跑或重建 sidecar）
set -e

URL="${KIBANA_URL:-http://localhost:5601}"
USER="${KIBANA_USERNAME:-elastic}"
PASS="${KIBANA_PASSWORD:?缺少 KIBANA_PASSWORD 环境变量}"
FILE=/opt/kibana-init/dashboards.ndjson

echo "[kibana-init] 等待 Kibana 就绪: $URL"
until curl -fs -u "$USER:$PASS" "$URL/api/status" -o /dev/null 2>/dev/null; do
  sleep 5
done
echo "[kibana-init] Kibana 就绪，导入看板..."

while true; do
  code=$(curl -s -o /tmp/import.json -w '%{http_code}' \
    -u "$USER:$PASS" -H 'kbn-xsrf: true' \
    -F "file=@$FILE;type=application/ndjson" \
    "$URL/api/saved_objects/_import?overwrite=true")
  if [ "$code" = "200" ] && grep -q '"success":true' /tmp/import.json; then
    echo "[kibana-init] 看板导入成功: $(grep -o '"successCount":[0-9]*' /tmp/import.json)"
    break
  fi
  echo "[kibana-init] 导入失败(HTTP $code)，30s 后重试: $(head -c 300 /tmp/import.json 2>/dev/null)"
  sleep 30
done

echo "[kibana-init] 导入完成，进入保活"
sleep infinity
