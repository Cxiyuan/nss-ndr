# 镜像：从离线 tar 加载，目标机不拉取、不构建
# tar 已上传到 agent.images_dir（默认 /root/nss-agent）

{% from "agent/map.jinja" import agent with context %}

{% for img in agent.get('images', []) %}
{%   set safe = img.name | replace('/', '_') | replace(':', '_') %}
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
    - load: {{ agent.images_dir }}/{{ img.tar }}
    - force: False
{% endfor %}
