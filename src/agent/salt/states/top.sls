# 智能体顶层入口：日常幂等自愈
#   salt-call --local state.apply agent  （经 /srv/salt/agent.sls -> agent.top）
include:
  - agent.images
  - agent.containers.agent
