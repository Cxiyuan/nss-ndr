# ============================================================================
# 数据总线顶层入口：日常幂等自愈用
#   masterless: salt-call --local state.apply databus
#   salt-ssh  : salt-ssh databus state.apply databus
# 说明：容器之间真正依赖（先 ES 后 Kibana 等）在 deploy.sls 编排里表达，
#       这里只做"配置漂移修正"，依赖顺序由 restart_policy + 编排保证。
# ============================================================================

include:
  - databus.images
  - databus.network
  - databus.volumes
  - databus.configs
  - databus.containers.elasticsearch
  - databus.containers.redis
  - databus.containers.kibana
  - databus.containers.fleet-server
  - databus.containers.elastic-agent
  - databus.containers.logstash
  - databus.containers.zeek
  - databus.containers.agent
