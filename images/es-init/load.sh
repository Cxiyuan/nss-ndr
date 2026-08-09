#!/bin/sh
# 等待 ES 就绪后导入管道/ILM/模板；失败重试，循环执行（sidecar 常驻）

set -e

ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-}"
ES_PASS="${ES_PASS:-}"
ES_SECURITY="${ES_SECURITY:-false}"
CURL_AUTH=
[ -n "$ES_USER" ] && CURL_AUTH="-u ${ES_USER}:${ES_PASS}"

wait_es() {
  until curl -sk $CURL_AUTH "$ES_URL/_cluster/health" -o /dev/null 2>/dev/null; do
    echo "$(date) - 等待 ES 就绪..."
    sleep 5
  done
}

import_json() {
  local method=$1 path=$2 file=$3
  curl -sk $CURL_AUTH -X "$method" \
    -H "Content-Type: application/json" \
    --data-binary "@$file" \
    "$ES_URL$path" -o /dev/null -w "%{http_code}" | grep -qE "^2[0-9]{2}$" || {
      echo "$(date) - 导入失败: $method $path"
      return 1
    }
}

create_app_users() {
  [ "$ES_SECURITY" = "true" ] || return 0
  [ -n "$FB_PASSWORD" ] && [ -n "$KIBANA_PASSWORD" ] && [ -n "$XDR_PASSWORD" ] || {
    echo "warn: 缺少应用用户密码环境变量，跳过用户创建"
    return 1
  }
  create_user() {
    local name=$1 pass=$2 roles=$3
    curl -sk $CURL_AUTH -X POST "$ES_URL/_security/user/$name" \
      -H "Content-Type: application/json" \
      -d "{\"password\":\"$pass\",\"roles\":[\"$roles\"]}" \
      -o /dev/null -w "%{http_code}" | grep -qE "^2[0-9]{2}$" \
      && echo "$(date) - 已创建/更新用户 $name" \
      || echo "$(date) - 创建用户 $name 失败"
  }
  create_user filebeat "$FB_PASSWORD" superuser
  create_user kibana_system "$KIBANA_PASSWORD" kibana_system
  create_user xdr-push "$XDR_PASSWORD" superuser
}

load_once() {
  create_app_users
  for f in /pipelines/*.json; do
    name=$(basename "$f" .json)
    echo "$(date) - 导入 pipeline: $name"
    import_json PUT "/_ingest/pipeline/$name" "$f" || return 1
  done

  for f in /pipelines/*.json.ilmpolicy; do
    name=$(basename "$f" .json.ilmpolicy)
    echo "$(date) - 导入 ILM: $name"
    import_json PUT "/_ilm/policy/$name" "$f" || return 1
  done

  for f in /pipelines/*.json.template; do
    name=$(basename "$f" .json.template)
    echo "$(date) - 导入 index template: $name"
    import_json PUT "/_index_template/$name" "$f" || return 1
  done
}

wait_es
echo "$(date) - ES 已就绪，开始导入配置"

# 循环执行：ES 重启/配置变更后可自动恢复
while true; do
  if load_once; then
    echo "$(date) - 配置导入完成"
  else
    echo "$(date) - 部分导入失败，10s 后重试"
  fi
  sleep "${ES_INIT_INTERVAL:-300}"
done
