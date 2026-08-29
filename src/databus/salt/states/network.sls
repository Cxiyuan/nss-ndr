# ============================================================================
# 自定义网络 nss-net 192.168.250.0/24
# 注意：Salt 3006.9 的 docker_network.present 在网络已存在时检查有 bug
#       （KeyError: 'Config'），改用 cmd.run 幂等创建。
# ============================================================================

ensure-nss-network:
  cmd.run:
    - name: docker network create --driver bridge --subnet 192.168.250.0/24 nss-net
    - unless: docker network inspect nss-net >/dev/null 2>&1
