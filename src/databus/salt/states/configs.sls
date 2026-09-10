# ============================================================================
# 业务配置统一下发（方案 C：配置全在宿主机 /opt/nss/ndr/，容器 bind 挂载）
# ----------------------------------------------------------------------------
# 执行位置：salt-minion 容器内（minion bind /opt/nss/ndr:/opt/nss/ndr 可写）
# 源：fileserver salt://databus/files/...（仓库 src/databus/salt/files/）
# 目标：宿主机 /opt/nss/ndr/<app>/...（业务容器各自 bind 只读子目录）
# 说明：
#   - vault.hcl / salt 模板(minion.tmpl/master.tmpl 等) 属引导配置，
#     仍由镜像烘焙（salt/vault 容器启动前需要）；本文件只管业务配置
#   - .env 动态凭据由 vault-render-env.sh 生成（见 vault-seed.sls），
#     不在本文件管理
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

{% set cfg_root = databus.get('config_root', '/opt/nss/ndr') %}

# 统一建目录（可写，salt-minion 用）
ensure-config-root:
  file.directory:
    - name: {{ cfg_root }}
    - makedirs: True
    - user: root
    - group: root
    - mode: "755"

# ---- 业务配置文件清单 ----
{% set configs = [
  {'src': 'salt://databus/files/zeek/local.zeek',                  'dst': cfg_root ~ '/zeek/local.zeek', 'mode': '644'},
  {'src': 'salt://databus/files/zeek/scripts/detect.zeek',         'dst': cfg_root ~ '/zeek/scripts/detect.zeek', 'mode': '644'},
  {'src': 'salt://databus/files/logstash/pipeline/zeek-pipeline.conf', 'dst': cfg_root ~ '/logstash/pipeline/zeek-pipeline.conf', 'mode': '644'},
  {'src': 'salt://databus/files/logstash/config/logstash.yml',     'dst': cfg_root ~ '/logstash/config/logstash.yml', 'mode': '644'},
  {'src': 'salt://databus/files/logstash/config/pipelines.yml',    'dst': cfg_root ~ '/logstash/config/pipelines.yml', 'mode': '644'},
  {'src': 'salt://databus/files/logstash/config/log4j2.properties','dst': cfg_root ~ '/logstash/config/log4j2.properties', 'mode': '644'},
  {'src': 'salt://databus/files/logstash/config/jvm.options',      'dst': cfg_root ~ '/logstash/config/jvm.options', 'mode': '644'},
  {'src': 'salt://databus/files/kibana/kibana.yml',                'dst': cfg_root ~ '/kibana/kibana.yml', 'mode': '644'},
  {'src': 'salt://databus/files/redis/redis.conf',                 'dst': cfg_root ~ '/redis/redis.conf', 'mode': '644'},
  {'src': 'salt://databus/files/elastic-agent/fleet-elastic-agent.yml', 'dst': cfg_root ~ '/elastic-agent/fleet-elastic-agent.yml', 'mode': '644'},
  {'src': 'salt://databus/files/vault/vault.hcl',                  'dst': cfg_root ~ '/vault/vault.hcl', 'mode': '644'},
  {'src': 'salt://databus/files/epr/epr-proxy.py',                 'dst': cfg_root ~ '/epr/epr-proxy.py', 'mode': '644'}
] %}

{% for cfg in configs %}
{{ cfg.dst }}:
  file.managed:
    - source: {{ cfg.src }}
    - user: root
    - group: root
    - mode: {{ cfg.mode }}
    - makedirs: True
    - require:
      - file: ensure-config-root
{% endfor %}
