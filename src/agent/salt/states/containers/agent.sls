# 智能体容器：消费 analysis:events，固定 IP 192.168.250.80

include:
  - agent.images
  - agent.configs

{% from "agent/map.jinja" import agent with context %}
{% from "agent/map.jinja" import env_get with context %}

nss-ndr-agent:
  docker_container.running:
    - image: nss-ndr/agent:0.1.1
    - name: {{ agent.container_name }}
    - restart_policy: unless-stopped
    - user: agent
    - entrypoint: ["python", "-m", "app"]
    - command: ["worker"]
    - binds:
        - {{ agent.config_dir }}:/opt/nss-ndr-agent/config:ro
    - networks:
        - {{ agent.network }}:
            - ipv4_address: {{ agent.fixed_ip }}
            - aliases:
                - agent
    - environment:
        - TZ={{ agent.get('tz', 'Asia/Shanghai') }}
        - REDIS_URL=redis://redis:6379/0
        - REDIS_PASSWORD={{ env_get('REDIS_PASSWORD') }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - ELASTICSEARCH_USERNAME={{ env_get('ELASTIC_USERNAME') }}
        - ELASTICSEARCH_PASSWORD={{ env_get('ELASTIC_PASSWORD') }}
        - EDGE_LLM_BASE_URL={{ env_get('EDGE_LLM_BASE_URL') }}
        - EDGE_LLM_API_KEY={{ env_get('EDGE_LLM_API_KEY') }}
        - EDGE_LLM_MODEL={{ env_get('EDGE_LLM_MODEL') }}
        - CLOUD_LLM_BASE_URL={{ env_get('CLOUD_LLM_BASE_URL') }}
        - CLOUD_LLM_API_KEY={{ env_get('CLOUD_LLM_API_KEY') }}
        - CLOUD_LLM_MODEL={{ env_get('CLOUD_LLM_MODEL') }}
        # AGENT_DRY_RUN: 0=生产模式（写 verdict/entity/ES/Redis Lua）；1=只读消费
        # 上游 agent-setup.sh 已默认写入 0；此处兜底 '0' 防止 .env 未及时刷新
        - AGENT_DRY_RUN={{ env_get('AGENT_DRY_RUN') or '0' }}
        - AGENT_LOG_LEVEL=INFO
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD", "python", "-c", "import sys; sys.exit(0 if b'python' in open('/proc/1/cmdline','rb').read() else 1)"]
        - interval: 30000000000
        - timeout: 5000000000
        - retries: 5
        - start_period: 30000000000
    - require:
      - docker_image: nss-ndr/agent:0.1.1
      - file: /etc/nss-ndr/agent/agent.yaml
      - file: /etc/nss-ndr/agent/providers.yaml
      - file: /etc/nss-ndr/agent/rules/beh-rules.yaml
