# NSS-NDR Kibana 看板初始化器（sidecar）
# 参照 SO 3.1.0 做法：部署后自动导入 NDR 看板（导出自 Security Onion Kibana，
# 已改名 NDR - * 并按本项目 ES 模板修复 .keyword 字段）

FROM alpine:3.20

RUN apk add --no-cache curl

COPY files/import-dashboards.sh /usr/local/bin/import-dashboards.sh
COPY files/dashboards.ndjson /opt/kibana-init/dashboards.ndjson
RUN chmod +x /usr/local/bin/import-dashboards.sh

ENTRYPOINT ["/usr/local/bin/import-dashboards.sh"]
