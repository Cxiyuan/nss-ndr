# ============================================================================
# Fleet 初始化：default output / agent policies / enrollment keys /
# Zeek Integration package policy
# ----------------------------------------------------------------------------
# 复用 src/databus/scripts/auto-init.sh 第 6~9 步的 API 交互逻辑，
# 生成 FLEET_ENROLLMENT_TOKEN / ELASTIC_AGENT_ENROLLMENT_TOKEN 写回 .env。
# 幂等：接口均做"已存在则跳过"。
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

# fleet-setup.sh 已烘焙进 salt-minion 镜像 /opt/nss-ndr/scripts/
run-fleet-setup:
  cmd.run:
    - name: /opt/nss-ndr/scripts/fleet-setup.sh
    - unless: test -f /etc/nss-ndr/.fleet-setup.done
    - require_in:
      - file: mark-fleet-setup-done

mark-fleet-setup-done:
  file.touch:
    - name: /etc/nss-ndr/.fleet-setup.done
    - unless: test -f /etc/nss-ndr/.fleet-setup.done
    - require:
      - cmd: run-fleet-setup
