# 前置预检：数据总线 ES/Redis 已运行（不阻断则部署无意义）

{% from "agent/map.jinja" import agent with context %}

precheck-databus-containers:
  cmd.run:
    - name: |
        for c in nss-ndr-elasticsearch nss-ndr-redis; do
          st=$(docker inspect -f '{{ '{{.State.Running}}' }}' "$c" 2>/dev/null || echo missing)
          if [ "$st" != "true" ]; then
            echo "[ERROR] 数据总线容器 $c 未运行（当前: $st）" >&2
            exit 1
          fi
        done
        echo "OK: databus ES/Redis running"
    - failhard: True
