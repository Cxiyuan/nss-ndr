# 部署后验证：容器状态 + 消费组存在 + worker 日志

{% from "agent/map.jinja" import agent with context %}
{% from "agent/map.jinja" import env_get with context %}

verify-agent-container:
  cmd.run:
    - name: |
        docker ps --filter "name=nss-ndr-agent" --format "{{ '{{.Names}} {{.Status}} {{.Image}}' }}"
    - failhard: False

verify-agent-consumer-group:
  cmd.run:
    - name: |
        docker exec nss-ndr-redis redis-cli -a "{{ env_get('REDIS_PASSWORD') }}" --no-auth-warning \
          XINFO GROUPS analysis:events 2>/dev/null | grep -A1 "analysis-group" || echo "消费组未找到（Stream 可能暂无数据，需 logstash 双写事件后才自动出现）"
    - failhard: False

verify-agent-logs:
  cmd.run:
    - name: |
        docker logs --tail 20 nss-ndr-agent 2>&1 | tail -20
    - failhard: False
