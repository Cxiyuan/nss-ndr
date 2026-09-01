# ============================================================================
# 镜像：从国内 GHCR 镜像源拉取（/etc/docker/daemon.json 已配 registry-mirrors）
# 自 2026-08-31 起：产品发布改为镜像直发，不再使用本地 offline tar
# ============================================================================

{% from "agent/map.jinja" import agent with context %}

{% for img in agent.get('images', []) %}
{%   set repo_tag = img.name | string %}
{%   if ':' in repo_tag %}
{%     set repo = repo_tag.rsplit(':', 1)[0] %}
{%     set tag = repo_tag.rsplit(':', 1)[1] %}
{%   else %}
{%     set repo = repo_tag %}
{%     set tag = 'latest' %}
{%   endif %}
"{{ img.name }}":
  docker_image.present:
    - name: {{ repo }}
    - tag: {{ tag }}
    # 不指定 load: / pull: 字段，由 docker daemon 按 daemon.json 的 registry-mirrors 拉取
    - force: False
{% endfor %}
