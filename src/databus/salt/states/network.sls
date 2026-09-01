# ============================================================================
# 自定义网络 nss-net 192.168.250.0/24
# ============================================================================
# 注：本机 nss-net 由 docker run --network nss-net 自动创建（见 pillar）。
# 此 state 文件保留空清单，state.apply 不会失败（modules.run 在空 SLS 上 OK）。
# 如果将来需要用 Salt 自动创建，改用：
#   module.run:
#     - name: docker.create_network
#     - ...
