# ============================================================================
# 外挂配置文件下发（只保留必须外挂的，其余已整合进镜像）
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

{% for cfg in databus.get('configs', []) %}
{{ cfg.dst }}:
  file.managed:
    - source: {{ cfg.src }}
    - user: root
    - group: root
    - mode: {{ cfg.mode }}
    - makedirs: True
{% endfor %}
