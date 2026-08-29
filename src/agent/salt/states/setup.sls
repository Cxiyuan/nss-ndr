# 智能体幂等初始化：ES 索引/ILM、Redis 消费组、.env 默认值

{% from "agent/map.jinja" import agent with context %}

copy-agent-setup-script:
  file.managed:
    - name: /opt/nss-ndr/scripts/agent-setup.sh
    - source: salt://agent/scripts/agent-setup.sh
    - user: root
    - group: root
    - mode: "700"
    - makedirs: True

run-agent-setup:
  cmd.run:
    - name: /opt/nss-ndr/scripts/agent-setup.sh
    - unless: test -f /etc/nss-ndr/.agent-setup.done
    - require:
      - file: copy-agent-setup-script
    - require_in:
      - file: mark-agent-setup-done

mark-agent-setup-done:
  file.touch:
    - name: /etc/nss-ndr/.agent-setup.done
    - require:
      - cmd: run-agent-setup
