# ============================================================================
# Salt Master + Salt API（nss-ndr/salt-master-api）
# ----------------------------------------------------------------------------
# 容器在 nss-net 网络内提供 ZeroMQ（4505/4506）+ REST API（8000）：
#   - 与本机 salt-minion 容器配对（同一 nss-net）
#   - 端口 publish 到 host 仅 8000（CherryPy REST），4505/4506 仅容器内使用
# 上下游依赖：
#   - 必须先于 salt-minion 启动（master 接收 minion 注册）
#   - 必须先于所有 databus.containers.* 启动（minion 通过 master 调度容器）
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import salt_master_api with context %}

nss-ndr-salt-master-api:
  docker_container.running:
    - image: {{ salt_master_api.image }}
    - restart_policy: unless-stopped
    # 容器默认非特权（uid 10002）；salt-master 不需要特权
    # network_mode 必须显式 nss-net（与线上容器一致；缺省会变 bridge 触发重建）
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    - binds:
        - nss-ndr-salt-log:/var/log/salt
        - /srv/salt:/srv/salt:ro       # 与 minion 共享 state file_roots（只读，内容由宿主机 scp 同步）
        - /srv/pillar:/srv/pillar:ro   # 与 minion 共享 pillar（只读）
        - /etc/nss-ndr:/etc/nss-ndr:ro # 读取 .env（动态 token），只读防误写
        - /var/run/docker.sock:/var/run/docker.sock
        - nss-ndr-salt-config:/etc/salt-master-api
        - nss-ndr-salt-run:/var/run/salt
        - nss-ndr-salt-cache:/var/cache/salt
    - networks:
        - nss-net:
            - ipv4_address: {{ salt_master_api.ip }}
            - aliases:
                - salt-master-api
                - salt
    - environment:
        - TZ={{ databus.tz }}
        - SALT_MASTER_INTERFACE=0.0.0.0
        - SALT_API_USER={{ salt_master_api.api_user }}
        - SALT_API_PASSWORD={{ salt_master_api.api_password }}
        - SALT_API_PORT={{ salt_master_api.api_port | string }}
        - PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
    - port_bindings:
        - "{{ databus.host_bind }}:{{ salt_master_api.api_port }}:{{ salt_master_api.api_port }}"
    - log_driver: json-file
    - require:
      - docker_image: {{ salt_master_api.image }}
      - docker_network: ensure-nss-net-present
      - docker_volume: nss-ndr-salt-config
      - docker_volume: nss-ndr-salt-run
      - docker_volume: nss-ndr-salt-cache
      - docker_volume: nss-ndr-salt-log
