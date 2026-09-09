# ============================================================================
# Zeek 8.2.2（host 网络，监听 ens192，输出 JSON 到 zeek-logs 卷）
# 与线上验证通过的容器一致：内联 command（不经启动脚本），
# logdir 由镜像内 local.zeek 的 default_logdir 指向 /usr/local/zeek/logs
# ============================================================================

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs

{% from "databus/map.jinja" import databus with context %}

nss-ndr-zeek:
  docker_container.running:
    - image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/zeek-databus:8.2.2
    - restart_policy: unless-stopped
    - detach: True
    - skip_translate: volumes
    - network_mode: host
    - cap_add:
        - NET_ADMIN
        - NET_RAW
        - SYS_ADMIN
    - devices:
        - /dev/net/tun:/dev/net/tun
    - binds:
        - nss-ndr-zeek-logs:/usr/local/zeek/logs
        # 方案 C：local.zeek/detect.zeek 由 salt 下发宿主机 /opt/nss/ndr/zeek, bind 进容器
        - /opt/nss/ndr/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro
        - /opt/nss/ndr/zeek/scripts:/usr/local/zeek/share/zeek/site/scripts:ro
    - command: bash -c "export PATH=/usr/local/zeek/bin:$PATH; cd /usr/local/zeek/share/zeek && exec zeek -i $ZEEK_INTERFACE site/local.zeek"
    - environment:
        - TZ={{ databus.tz }}
        - ZEEK_INTERFACE={{ databus.zeek_interface }}
    - log_driver: json-file
    - require:
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/zeek-databus:8.2.2
      - file: /opt/nss/ndr/zeek/local.zeek
      - file: /opt/nss/ndr/zeek/scripts/detect.zeek
