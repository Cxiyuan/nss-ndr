# 一键清理智能体（只清本项目，不影响数据总线与其他业务）

nss-ndr-agent:
  docker_container.absent:
    - force: True

nss-ndr-agent-data:
  docker_volume.absent:
    - force: True
    - require:
      - docker_container: nss-ndr-agent
