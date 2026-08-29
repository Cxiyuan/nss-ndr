# 智能体全流程编排（masterless: salt-call --local state.apply agent.deploy）
# 阶段：images -> configs -> 预检 databus -> setup（索引/消费组/.env）-> 容器 -> 验证

{% from "agent/map.jinja" import agent with context %}

deploy-agent-images:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.images

deploy-agent-configs:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.configs
    - require:
      - salt: deploy-agent-images

precheck-databus:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.bootstrap
    - require:
      - salt: deploy-agent-configs

deploy-agent-setup:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.setup
    - require:
      - salt: precheck-databus

deploy-agent-container:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.containers.agent
    - require:
      - salt: deploy-agent-setup

verify-agent:
  salt.state:
    - tgt: {{ agent.get('target', 'agent') }}
    - sls: agent.verify
    - require:
      - salt: deploy-agent-container
