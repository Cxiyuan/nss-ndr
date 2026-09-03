# 智能体幂等初始化：ES 索引/ILM、Redis 消费组、.env 默认值

{% from "agent/map.jinja" import agent with context %}

# agent-setup.sh 已烘焙进 salt-minion 镜像 /opt/nss-ndr/scripts/
run-agent-setup:
  cmd.run:
    - name: /opt/nss-ndr/scripts/agent-setup.sh
    - unless: test -f /etc/nss-ndr/.agent-setup.done
    - require_in:
      - file: mark-agent-setup-done

mark-agent-setup-done:
  file.touch:
    - name: /etc/nss-ndr/.agent-setup.done
    - require:
      - cmd: run-agent-setup
