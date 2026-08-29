# ============================================================================
# 数据总线全流程编排（从零部署 / 完整初始化）
# ----------------------------------------------------------------------------
# 用法：
#   masterless: salt-call --local state.apply databus.deploy
#   salt-ssh  : salt-ssh databus state.apply databus.deploy
#   master    : salt-run state.orchestrate databus.deploy
#
# 阶段顺序：
#   images -> network/volumes/configs -> es/redis -> 等 ES
#   -> 生成 KIBANA_SERVICE_TOKEN -> kibana -> 等 Kibana
#   -> 创建 Fleet output/policy/enrollment keys/Zeek Integration
#   -> fleet-server / elastic-agent / logstash / zeek -> 验证
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

deploy-images:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.images

deploy-network:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.network
    - require:
      - salt: deploy-images

deploy-volumes:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.volumes
    - require:
      - salt: deploy-images

deploy-configs:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.configs
    - require:
      - salt: deploy-images

deploy-es-redis:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls:
        - databus.containers.elasticsearch
        - databus.containers.redis
    - require:
      - salt: deploy-network
      - salt: deploy-volumes
      - salt: deploy-configs

wait-es-healthy:
  http.wait_for_successful_query:
    - name: http://localhost:9200/_cluster/health
    - username: {{ databus.creds.elastic_username }}
    - password: {{ databus.creds.elastic_password }}
    - status: 200
    - wait_for: 300
    - request_interval: 5
    - require:
      - salt: deploy-es-redis

deploy-bootstrap-tokens:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.bootstrap
    - require:
      - http: wait-es-healthy

deploy-kibana:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.kibana
    - require:
      - salt: deploy-bootstrap-tokens

wait-kibana-healthy:
  http.wait_for_successful_query:
    - name: http://localhost:5601/api/status
    - username: {{ databus.creds.elastic_username }}
    - password: {{ databus.creds.elastic_password }}
    - status: 200
    - wait_for: 300
    - request_interval: 5
    - require:
      - salt: deploy-kibana

deploy-fleet-setup:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.fleet-setup
    - require:
      - http: wait-kibana-healthy

deploy-apps:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls:
        - databus.containers.fleet-server
        - databus.containers.elastic-agent
        - databus.containers.logstash
        - databus.containers.zeek
        - databus.containers.agent
    - require:
      - salt: deploy-fleet-setup

verify-databus:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.verify
    - require:
      - salt: deploy-apps
