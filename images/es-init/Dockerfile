# NSS-NDR ES 初始化器（sidecar）
# 在 Elasticsearch 就绪后导入 ingest pipelines / ILM / 索引模板

FROM alpine:3.20

RUN apk add --no-cache curl jq

COPY pipelines/ /pipelines/
COPY load.sh /usr/local/bin/load.sh
RUN chmod +x /usr/local/bin/load.sh

ENTRYPOINT ["/usr/local/bin/load.sh"]
