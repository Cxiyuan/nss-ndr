# ============================================================================
# AI 分析智能体（nss-ndr/agent:0.1.1，worker 模式）
# 消费 Redis Stream（analysis:events）做 AI 分析，结果写回 ES
# 配置目录 /etc/nss-ndr/agent（agent.yaml / providers.yaml / rules/）由 Salt 下发
# ============================================================================

include:
  - databus.network
  - databus.configs

{% from "databus/map.jinja" import databus with context %}

deploy-agent-agent-yaml:
  file.managed:
    - name: /etc/nss-ndr/agent/agent.yaml
    - source: salt://databus/files/agent/agent.yaml
    - user: root
    - group: root
    - mode: "644"
    - makedirs: True

deploy-agent-providers-yaml:
  file.managed:
    - name: /etc/nss-ndr/agent/providers.yaml
    - source: salt://databus/files/agent/providers.yaml
    - user: root
    - group: root
    - mode: "644"

deploy-agent-beh-rules:
  file.managed:
    - name: /etc/nss-ndr/agent/rules/beh-rules.yaml
    - source: salt://databus/files/agent/rules/beh-rules.yaml
    - user: root
    - group: root
    - mode: "644"
    - makedirs: True

nss-ndr-agent:
  docker_container.running:
    - image: nss-ndr/agent:0.1.1
    - restart_policy: unless-stopped
    - user: agent
    - entrypoint: ["python", "-m", "app"]
    - command: ["worker"]
    - binds:
        - /etc/nss-ndr/agent:/opt/nss-ndr-agent/config:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.agent.ip }}
    - environment:
        - TZ={{ databus.tz }}
        - REDIS_URL=redis://redis:6379/0
        - REDIS_PASSWORD={{ databus.creds.redis_password }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - ELASTICSEARCH_USERNAME={{ databus.creds.elastic_username }}
        - ELASTICSEARCH_PASSWORD={{ databus.creds.elastic_password }}
        - EDGE_LLM_BASE_URL={{ databus.agent.llm.edge_base_url }}
        - EDGE_LLM_API_KEY={{ databus.agent.llm.edge_api_key }}
        - EDGE_LLM_MODEL={{ databus.agent.llm.edge_model }}
        - CLOUD_LLM_BASE_URL={{ databus.agent.llm.cloud_base_url }}
        - CLOUD_LLM_API_KEY={{ databus.agent.llm.cloud_api_key }}
        - CLOUD_LLM_MODEL={{ databus.agent.llm.cloud_model }}
        - AGENT_DRY_RUN={{ databus.agent.dry_run }}
        - AGENT_LOG_LEVEL={{ databus.agent.log_level }}
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD", "python", "-c", "import sys; sys.exit(0 if b'python' in open('/proc/1/cmdline','rb').read() else 1)"]
        - interval: 30000000000
        - timeout: 5000000000
        - start_period: 30000000000
        - retries: 5
    - require:
      - cmd: ensure-nss-network
      - file: /etc/nss-ndr/agent/agent.yaml
      - file: /etc/nss-ndr/agent/providers.yaml
      - file: /etc/nss-ndr/agent/rules/beh-rules.yaml
