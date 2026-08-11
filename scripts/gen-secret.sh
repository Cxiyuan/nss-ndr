#!/bin/bash
# 生成 k3s 部署凭据 deploy/k3s/25-secret.yaml（gitignored，不入库）
# - elastic 固定默认值 nss-ndr@2026（Kibana/ES 登录账号，与 Helm values.secrets 一致）
# - filebeat / kibana_system / xdr-push / redis 随机生成（内部服务账号）
# - Kibana 加密 key 随机生成（xpack.security/encryptedSavedObjects/reporting）
# 已存在则不覆盖，避免误改在跑环境。
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=deploy/k3s/25-secret.yaml
if [ -f "$TARGET" ]; then
  echo "已存在 $TARGET，跳过生成（如需重置请先删除该文件）"
  exit 0
fi

cat > "$TARGET" <<EOF
# 自动生成（scripts/gen-secret.sh）；elastic 密码固定默认值，其余随机
apiVersion: v1
kind: Secret
metadata:
  name: nss-ndr-secrets
  namespace: nss-ndr
type: Opaque
stringData:
  elastic-password: "nss-ndr@2026"
  filebeat-password: $(openssl rand -hex 16)
  kibana-password: $(openssl rand -hex 16)
  kibana-encryption-key: $(openssl rand -hex 32)
  kibana-encrypted-saved-objects-key: $(openssl rand -hex 32)
  kibana-reporting-key: $(openssl rand -hex 32)
  xdr-push-password: $(openssl rand -hex 16)
  redis-password: $(openssl rand -hex 16)
EOF

echo "已生成 $TARGET"
echo "  elastic 登录：elastic / nss-ndr@2026"
echo "  其余服务账号密码为随机值（可 cat $TARGET 查看）"
