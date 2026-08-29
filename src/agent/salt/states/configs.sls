# 配置文件下发到 /etc/nss-ndr/agent/（容器以只读方式挂载到 /opt/nss-ndr-agent/config）

{% from "agent/map.jinja" import agent with context %}

ensure-agent-config-dir:
  file.directory:
    - name: {{ agent.config_dir }}/rules
    - makedirs: True
    - user: root
    - group: root
    - mode: "755"

{% for cfg in agent.get('configs', []) %}
{{ cfg.dst }}:
  file.managed:
    - source: {{ cfg.src }}
    - user: root
    - group: root
    - mode: {{ cfg.mode }}
    - makedirs: True
    - require:
      - file: ensure-agent-config-dir
{% endfor %}
