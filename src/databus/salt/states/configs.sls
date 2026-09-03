# ============================================================================
# 外挂配置文件下发（只保留必须外挂的，其余已整合进镜像）
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

# 保底 state(配置已烘焙进镜像;目录保留供 .env/动态 token 使用)
ensure-env-dir:
  file.directory:
    - name: /etc/nss-ndr
    - makedirs: True
    - user: root
    - group: root
    - mode: "755"

{% for cfg in databus.get('configs', []) %}
{{ cfg.dst }}:
  file.managed:
    - source: {{ cfg.src }}
    - user: root
    - group: root
    - mode: {{ cfg.mode }}
    - makedirs: True
{% endfor %}
