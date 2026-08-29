# ============================================================================
# 镜像：从 offline tar 加载，目标机不拉取、不构建
# 镜像 tar 已上传到 databus.images_dir（默认 /root/nss-ndr/images）
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

{% for img in databus.get('images', []) %}
{%   set safe = img.name | replace('/', '__') | replace(':', '__') %}
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
    - load: {{ databus.images_dir }}/{{ img.tar }}
    - force: False
{% endfor %}
