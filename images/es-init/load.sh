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

wait_security() {
  [ "$ES_SECURITY" = "true" ] || return 0
  # ES 首次启动后安全插件需要初始化（reserved 用户/安全索引），
  # 直接建用户会 401；等 elastic 认证成功再继续，避免初始化时序问题
  until curl -sk $CURL_AUTH "$ES_URL/_security/_authenticate" -o /dev/null 2>/dev/null; do
    echo "$(date) - 等待 ES 安全插件就绪..."
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
  [ -n "$FB_PASSWORD" ] && [ -n "$XDR_PASSWORD" ] || {
    echo "warn: 缺少应用用户密码环境变量，跳过用户创建"
    return 1
  }
  # 校验应用用户密码是否已是期望值；一致则跳过（避免每次重启重置密码造成瞬时认证失败）
  check_user_pass() {
    local name=$1 pass=$2
    # 必须校验 HTTP 2xx：curl 对 401 默认退出码为 0，只看退出码会把未设置密码误判为已正确
    curl -sk -u "$name:$pass" -o /dev/null -w "%{http_code}" "$ES_URL/_security/_authenticate" 2>/dev/null | grep -q "^2"
  }
  create_user() {
    local name=$1 pass=$2 roles=$3
    if check_user_pass "$name" "$pass"; then
      echo "$(date) - 用户 $name 密码已正确，跳过"
      return 0
    fi
    local code
    code=$(curl -sk $CURL_AUTH -X PUT "$ES_URL/_security/user/$name" \
      -H "Content-Type: application/json" \
      -d "{\"password\":\"$pass\",\"roles\":[\"$roles\"]}" \
      -o /dev/null -w "%{http_code}")
    case "$code" in
      2*)
        echo "$(date) - 已创建/更新用户 $name"
        ;;
      *)
        # 内置保留用户不能用 PUT 创建/更新，改用改密 API
        code=$(curl -sk $CURL_AUTH -X POST "$ES_URL/_security/user/$name/_password" \
          -H "Content-Type: application/json" \
          -d "{\"password\":\"$pass\"}" \
          -o /dev/null -w "%{http_code}")
        if [ "$code" = "200" ]; then
          echo "$(date) - 已设置保留用户 $name 密码"
        else
          echo "$(date) - 创建用户 $name 失败 (_password=$code)"
        fi
        ;;
    esac
  }
  create_user filebeat "$FB_PASSWORD" superuser
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
wait_security
echo "$(date) - ES 已就绪，开始导入配置"

# 循环执行：ES 重启/配置变更后可自动恢复
while true; do
  if load_once; then
    echo "$(date) - 配置导入完成"
  else
    echo "$(date) - 部分导入失败，10s 后重试"
  fi
  sleep "${ES_INIT_INTERVAL:-30}"
done
