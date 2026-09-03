# ============================================================================
# Vault 单节点配置(凭据管理:应用密码唯一来源)
# - file 后端持久化到命名卷 nss-vault-data:/vault/file
# - 仅监听 nss-net 内网 8200(容器外不发布,运维走 docker exec / 内网)
# - disable_mlock: 容器内无需 IPC_LOCK
# ============================================================================
storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

disable_mlock = true
api_addr      = "http://vault:8200"
ui            = true
