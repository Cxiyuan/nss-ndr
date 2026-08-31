# ============================================================================
# 自动初始化：
#   1) /root/deploy.sh —— masterless 部署编排脚本（salt-call 分阶段，幂等）
#   2) /etc/systemd/system/nss-ndr-bootstrap.service —— 开机/重启后自动执行 deploy.sh
# 重复执行 deploy.sh 仅做差异修复（盐状态 + file.managed 幂等），
# 不会重复创建容器/策略/集成。
# ============================================================================

deploy-orchestrator-script:
  file.managed:
    - name: /root/deploy.sh
    - source: salt://databus/files/deploy.sh
    - user: root
    - group: root
    - mode: "755"

deploy-bootstrap-service:
  file.managed:
    - name: /etc/systemd/system/nss-ndr-bootstrap.service
    - source: salt://databus/files/nss-ndr-bootstrap.service
    - user: root
    - group: root
    - mode: "644"

reload-systemd-daemon:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: deploy-bootstrap-service

enable-bootstrap-service:
  cmd.run:
    - name: systemctl enable nss-ndr-bootstrap.service
    - onchanges:
      - file: deploy-bootstrap-service
