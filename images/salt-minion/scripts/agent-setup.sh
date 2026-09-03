#!/usr/bin/env bash
# ============================================================
# 智能体幂等初始化（Salt agent.setup 调用）
#   1. 创建 ES 索引 + ILM 策略（verdict / assets / events）
#   2. 创建 Redis 消费组 analysis-group（Stream 不存在时 mkstream 兜底）
#   3. .env 补充 AGENT_* / LLM 配置默认值（缺失时追加空值）
# 依赖：数据总线 ES/Redis 已运行，/etc/nss-ndr/.env 已就绪
# ============================================================
set -euo pipefail

ENV_FILE="${NSS_ENV_FILE:-/etc/nss-ndr/.env}"
ES_URL="http://localhost:9200"

ES_USER=$(grep '^ELASTIC_USERNAME=' "$ENV_FILE" | cut -d= -f2-)
ES_PASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
REDIS_PASS=$(grep '^REDIS_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
STREAM="${REDIS_STREAM_NAME:-analysis:events}"

log() { echo -e "\n===== $1 ====="; }

append_kv() {
  local KEY="$1" VAL="${2:-}"
  if grep -q "^$KEY=" "$ENV_FILE"; then
    return 0
  fi
  echo "$KEY=$VAL" >> "$ENV_FILE"
  echo "  ✓ $KEY 已追加（默认空）"
}

log "1) ES 索引 + ILM 策略"
curl -fsS -u "$ES_USER:$ES_PASS" -X PUT "$ES_URL/_ilm/policy/nss-ndr-agent-policy" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"rollover":{"max_age":"7d","max_size":"20gb"}}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' \
  >/dev/null 2>&1 || echo "  (ILM 已存在或不可用，跳过)"

for idx in nss-ndr-agent-verdict nss-ndr-agent-assets nss-ndr-agent-events; do
  curl -fsS -u "$ES_USER:$ES_PASS" -X PUT "$ES_URL/$idx" -H "Content-Type: application/json" \
    -d '{"settings":{"number_of_shards":1,"number_of_replicas":1}}' >/dev/null 2>&1 \
    && echo "  ✓ $idx" || echo "  ($idx 已存在或创建失败，忽略)"
done

log "2) Redis 消费组"
docker exec nss-ndr-redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
  XGROUP CREATE "$STREAM" analysis-group 0 MKSTREAM 2>/dev/null \
  && echo "  ✓ analysis-group 已创建" || echo "  (analysis-group 已存在，幂等跳过)"

log "3) .env 默认值"
# LLM 本地边缘：默认指向本机 llm-server 容器（nss-net 网络内 alias）。
# llm-server 镜像默认未设置 LLM_API_KEY，留空。
# 若需要切到云端高阶，部署后编辑 /etc/nss-ndr/.env 覆盖以下三个变量即可。
append_kv "EDGE_LLM_BASE_URL" "http://llm-server:8080/v1"
append_kv "EDGE_LLM_API_KEY" ""
append_kv "EDGE_LLM_MODEL" "Qwen3-0.6B-Q8_0"
append_kv "CLOUD_LLM_BASE_URL" ""
append_kv "CLOUD_LLM_API_KEY" ""
append_kv "CLOUD_LLM_MODEL" ""
# 0 = 生产模式（写 verdict / entity / ES / Redis Lua）；1 = 只读消费、不写回
# 修复点：早期默认 dry_run=1 导致 agent 永远走"无 LLM 兜底 uncertain low"分支
append_kv "AGENT_DRY_RUN" "0"

echo -e "\n===== agent-setup.sh 完成 ====="
