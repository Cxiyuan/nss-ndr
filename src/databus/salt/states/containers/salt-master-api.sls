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
  - databus.images

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import salt_master_api with context %}

# Salt master-api 容器初始化：写入 api 账号密码到 .env（仅首次）
# 容器 entrypoint 用 SALT_API_PASSWORD_HASHED 注入系统用户 saltapi
{% if salt_master_api.api_password %}
init-salt-api-account:
  cmd.run:
    - name: |
        grep -q '^SALT_API_PASSWORD=' /etc/nss-ndr/.env \
          || echo 'SALT_API_PASSWORD={{ salt_master_api.api_password }}' >> /etc/nss-ndr/.env
        chmod 600 /etc/nss-ndr/.env
    - unless: grep -q '^SALT_API_PASSWORD=' /etc/nss-ndr/.env
    - require_in:
      - docker_container: nss-ndr-salt-master-api
{% endif %}

nss-ndr-salt-master-api:
  docker_container.running:
    - image: {{ salt_master_api.image }}
    - restart_policy: unless-stopped
    # 容器默认非特权（uid 10002）；salt-master 不需要特权
    - binds:
        - nss-ndr-salt-config:/etc/salt-master-api
        - nss-ndr-salt-run:/var/run/salt
        - nss-ndr-salt-cache:/var/cache/salt
        - nss-ndr-salt-log:/var/log/salt
        - /srv/salt:/srv/salt:rw       # 与 minion 共享 state file_roots
        - /srv/pillar:/srv/pillar:rw   # 与 minion 共享 pillar
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
    - port_bindings:
        - "{{ databus.host_bind }}:{{ salt_master_api.api_port }}:{{ salt_master_api.api_port }}"
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:{{ salt_master_api.api_port }}/health || (echo > /dev/tcp/127.0.0.1/4505) >/dev/null 2>&1 || exit 1"]
        - interval: 30000000000
        - timeout: 5000000000
        - retries: 5
        - start_period: 60000000000
    - require:
      - docker_image: {{ salt_master_api.image }}
      - docker_network: nss-net
      - docker_volume: nss-ndr-salt-config
      - docker_volume: nss-ndr-salt-run
      - docker_volume: nss-ndr-salt-cache
      - docker_volume: nss-ndr-salt-log