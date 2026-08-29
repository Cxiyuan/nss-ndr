#!/usr/bin/env bash
# ============================================================
# 生成 KIBANA_SERVICE_TOKEN 并写回 .env（仅需 ES，不依赖 Kibana）
# ----------------------------------------------------------------------------
# 编排中在 Kibana 启动【之前】执行（deploy.sls: deploy-bootstrap-tokens）
# 对应 auto-init.sh 第 3 步的逻辑。
# 幂等：由 bootstrap.sls 的 unless（.bootstrap.done）控制，只执行一次。
# 用法：/opt/nss-ndr/scripts/gen-kibana-token.sh
# ============================================================
set -euo pipefail

ENV_FILE="${NSS_ENV_FILE:-/etc/nss-ndr/.env}"
ES_URL="http://localhost:9200"

SUPER_USER="elastic"
SUPER_PASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)

if [[ -z "$SUPER_PASS" ]]; then
  echo "[ERROR] .env 中没有 ELASTIC_PASSWORD" >&2
  exit 1
fi

KIBANA_TOKEN=$(curl -fsS -X POST -u "$SUPER_USER:$SUPER_PASS" \
  "$ES_URL/_security/service/elastic/kibana/credential/token" |
  python3 -c "import sys,json; print(json.load(sys.stdin)['token']['value'])")

if grep -q "^KIBANA_SERVICE_TOKEN=" "$ENV_FILE"; then
  python3 - "$KIBANA_TOKEN" "$ENV_FILE" <<'PYEOF'
import re, sys
key = "KIBANA_SERVICE_TOKEN"; val = sys.argv[1]; path = sys.argv[2]
content = open(path).read()
content = re.sub(r'^'+key+r'=.*$', f'{key}={val}', content, count=1, flags=re.MULTILINE)
open(path, 'w').write(content)
PYEOF
else
  echo "KIBANA_SERVICE_TOKEN=$KIBANA_TOKEN" >> "$ENV_FILE"
fi
echo "  ✓ KIBANA_SERVICE_TOKEN 已生成并写入 $ENV_FILE"
