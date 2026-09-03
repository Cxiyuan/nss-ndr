# ============================================================================
# Vault 凭据派生:从 Vault 拉取基础密码生成 /etc/nss-ndr/.env(幂等合并)
# ----------------------------------------------------------------------------
# 执行位置:salt-minion 容器(VAULT_TOKEN 经容器 env 注入,见 salt-minion.sls)
# 编排位置:deploy.sls 在 deploy-configs 之后、bootstrap(生成动态 token)之前
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

# vault-render-env.sh 已烘焙进 salt-minion 镜像 /opt/nss-ndr/scripts/
run-vault-render:
  cmd.run:
    - name: /opt/nss-ndr/scripts/vault-render-env.sh
