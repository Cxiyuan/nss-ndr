#!/bin/bash
# 生成 NSS-NDR 数据总线 TLS 证书（CA / logstash 服务端 / filebeat 客户端）
# 并创建 k8s Secret nss-ndr-certs（在部署机执行）
set -e

NS="${1:-nss-ndr}"
DIR=$(mktemp -d)
CNF="$DIR/openssl.cnf"

cat > "$CNF" <<EOF
[req]
distinguished_name = dn
req_extensions = ext
[dn]
[ext]
subjectAltName = DNS:nss-logstash,DNS:localhost,IP:127.0.0.1
EOF

echo "== 生成 CA =="
openssl genrsa -out "$DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$DIR/ca.key" -sha256 -days 3650 \
  -out "$DIR/ca.crt" -subj "/CN=nss-ndr-ca"

echo "== 生成 Logstash 服务端证书 =="
openssl genrsa -out "$DIR/logstash.key" 2048 2>/dev/null
openssl req -new -key "$DIR/logstash.key" -out "$DIR/logstash.csr" -subj "/CN=nss-logstash" -config "$CNF"
openssl x509 -req -in "$DIR/logstash.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/logstash.crt" -days 3650 -sha256 -extfile "$CNF" -extensions ext

echo "== 生成 filebeat 客户端证书 =="
openssl genrsa -out "$DIR/filebeat.key" 2048 2>/dev/null
openssl req -new -key "$DIR/filebeat.key" -out "$DIR/filebeat.csr" -subj "/CN=nss-filebeat"
openssl x509 -req -in "$DIR/filebeat.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/filebeat.crt" -days 3650 -sha256

kubectl -n "$NS" create secret generic nss-ndr-certs \
  --from-file=ca.crt="$DIR/ca.crt" \
  --from-file=logstash.crt="$DIR/logstash.crt" \
  --from-file=logstash.key="$DIR/logstash.key" \
  --from-file=filebeat.crt="$DIR/filebeat.crt" \
  --from-file=filebeat.key="$DIR/filebeat.key" \
  --dry-run=client -o yaml | kubectl apply -f -

rm -rf "$DIR"
echo "Secret nss-ndr-certs 已创建（namespace: $NS）"
