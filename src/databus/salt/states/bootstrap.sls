# ============================================================================
# 动态 token 生成（KIBANA_SERVICE_TOKEN / FLEET_ENROLLMENT_TOKEN /
# ELASTIC_AGENT_ENROLLMENT_TOKEN）
# ----------------------------------------------------------------------------
# 本阶段只做 Kibana 启动【前】需要的事：生成 KIBANA_SERVICE_TOKEN（仅需 ES）。
# Fleet policy / enrollment keys / Zeek Integration 在 Kibana 启动后由
# fleet-setup.sls 处理（见 deploy.sls 编排顺序）。
# 幂等：生成成功后创建标记文件，避免重复生成导致 .env 被覆盖。
# 从零重装时删除 /etc/nss-ndr/.env 与 /etc/nss-ndr/.bootstrap.done 即可。
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

ensure-env-dir:
  file.directory:
    - name: /etc/nss-ndr
    - makedirs: True
    - user: root
    - group: root
    - mode: "755"

copy-gen-kibana-token-script:
  file.managed:
    - name: /opt/nss-ndr/scripts/gen-kibana-token.sh
    - source: salt://databus/scripts/gen-kibana-token.sh
    - user: root
    - group: root
    - mode: "700"
    - makedirs: True

generate-kibana-service-token:
  cmd.run:
    - name: /opt/nss-ndr/scripts/gen-kibana-token.sh
    - unless: test -f /etc/nss-ndr/.bootstrap.done
    - require:
      - file: copy-gen-kibana-token-script
    - require_in:
      - file: mark-bootstrap-done

mark-bootstrap-done:
  file.touch:
    - name: /etc/nss-ndr/.bootstrap.done
    - require:
      - cmd: generate-kibana-service-token
