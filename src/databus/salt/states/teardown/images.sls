# ============================================================================
# 可选：删除数据总线镜像（谨慎使用，删除后需重新 load tar）
# 用法：salt-call --local state.apply databus.teardown.images
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

{% for img in databus.get('images', []) %}
{{ img.name }}:
  docker_image.absent:
    - force: True
{% endfor %}
