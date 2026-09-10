# ============================================================================
# 数据总线全流程编排（从零部署 / 完整初始化）
# ----------------------------------------------------------------------------
# 用法：
#   master 容器: salt-run state.orchestrate databus.deploy
#   master API : curl -k https://<master>:8000/run (POST body: client=local_async,
#                tgt=databus, fun=state.orchestrate, arg=databus.deploy)
#   masterless : （兼容）salt-call --local state.apply databus.deploy
#
# 阶段顺序（2026-09-08 重构：vault 纳入 salt 管理）：
#   images -> network/volumes/configs
#   -> salt-master-api -> salt-minion
#   -> vault（init/unseal/kv-seed，seed 密码来自 pillar creds）
#   -> vault-seed（vault 就绪后从 kv 读基础密码派生 /opt/nss/ndr/.env）
#   -> es/redis -> 等 ES
#   -> 生成 KIBANA_SERVICE_TOKEN -> kibana -> 等 Kibana
#   -> 创建 Fleet output/policy/enrollment keys/Zeek Integration
#   -> fleet-server / elastic-agent / logstash / zeek / llm-server -> 验证
#
# 注意：vault-seed 必须在 minion 起来后执行（vault-render-env 在 minion 内跑），
#       且 vault 容器必须先在 minion 上部署完成（bootstrap 自管 init/unseal/seed）。
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

deploy-salt-master-api:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.salt-master-api
    - require:
      - salt: deploy-network
      - salt: deploy-volumes

deploy-salt-minion:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.salt-minion
    - require:
      - salt: deploy-salt-master-api

# 业务配置统一下发（方案 C）：minion bind /opt/nss/ndr 后执行 file.managed
# 下发业务配置（zeek/logstash/kibana/redis/elastic-agent/vault.hcl）到 /opt/nss/ndr
deploy-configs:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.configs
    - require:
      - salt: deploy-salt-minion

# Vault 容器（2026-09-08 重构：纳入 salt 管理）
# vault-bootstrap 幂等：init → unseal → RO token → kv seed(elastic/redis/kibana)
# seed 密码来自容器 env（SEED_*，由 pillar creds 渲染注入）
# vault.hcl 由 configs 下发到 /opt/nss/ndr/vault（require deploy-configs）
deploy-vault:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.vault
    - require:
      - salt: deploy-network
      - salt: deploy-volumes
      - salt: deploy-salt-minion
      - salt: deploy-configs

# vault-seed：vault 就绪后从 kv 读基础密码派生 /opt/nss/ndr/.env
# RO token 经共享卷 nss-vault-secrets 传入 minion（vault-render-env 自动读取）
deploy-vault-seed:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.vault-seed
    - require:
      - salt: deploy-vault

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
      - salt: deploy-salt-minion
      - salt: deploy-vault-seed

wait-es-healthy:
  http.wait_for_successful_query:
    - name: http://elasticsearch:9200/_cluster/health
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

# 本地 EPR（自定义 zeek 包 47 dataset；Kibana Fleet 从中安装）
# 上游 epr.elastic.co 的 zeek-5.0.1 只有 43 dataset，缺 analyzer/postgresql/
# quic/websocket，fleet-setup 提交 47 streams 会 404。
deploy-epr:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.epr
    - require:
      - salt: deploy-network
      - salt: deploy-volumes
      - salt: deploy-configs
      - salt: deploy-salt-minion

# EPR 需索引 29903 个包（~3 分钟）才开始监听 8080
wait-epr-ready:
  http.wait_for_successful_query:
    - name: http://epr:8080/
    - status: 200
    - wait_for: 900
    - request_interval: 15
    - require:
      - salt: deploy-epr

deploy-kibana:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.kibana
    - require:
      - salt: deploy-bootstrap-tokens
      - http: wait-epr-ready

wait-kibana-healthy:
  http.wait_for_successful_query:
    - name: http://kibana:5601/api/status
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
      - http: wait-epr-ready

deploy-llm-server:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.containers.llm-server
    - require:
      - salt: deploy-fleet-setup

deploy-apps:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls:
        - databus.containers.fleet-server
        - databus.containers.elastic-agent
        - databus.containers.logstash
        - databus.containers.zeek
    - require:
      - salt: deploy-llm-server

verify-databus:
  salt.state:
    - tgt: {{ databus.get('target', 'databus') }}
    - sls: databus.verify
    - require:
      - salt: deploy-apps
