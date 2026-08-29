# ============================================================================
# 部署后验证：agent online + logs-zeek.* 数据流 + ECS 字段归一化
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

verify-zeek-datastream:
  cmd.run:
    - name: |
        curl -fsS -u {{ databus.creds.elastic_username }}:{{ databus.creds.elastic_password }} \
          "http://localhost:9200/_cat/indices/.ds-logs-zeek.*?h=index,docs.count&s=index" | head -20
    - failhard: False

verify-ecs-fields:
  cmd.run:
    - name: |
        curl -fsS -u {{ databus.creds.elastic_username }}:{{ databus.creds.elastic_password }} \
          "http://localhost:9200/.ds-logs-zeek.connection-*/_search?size=1" \
          -H "Content-Type: application/json" \
          -d '{"query":{"match_all":{}}}' | python3 -c "
        import sys, json
        d = json.load(sys.stdin)
        if d.get('hits', {}).get('hits'):
            src = d['hits']['hits'][0]['_source']
            print('source.ip=', src.get('source', {}).get('ip'))
            print('dest.ip=', src.get('destination', {}).get('ip'))
            print('transport=', src.get('network', {}).get('transport'))
            print('dataset=', src.get('event', {}).get('dataset'))
        else:
            print('暂无数据')
        "
    - failhard: False
