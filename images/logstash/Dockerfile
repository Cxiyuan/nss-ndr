# NSS-NDR Logstash：数据总线汇聚层（manager 接收 -> redis 缓冲 -> search 写 ES）
# 架构对齐 Security Onion 3.1.0：双 pipeline + Redis 缓冲 + metadata.pipeline 路由

FROM docker.elastic.co/logstash/logstash:9.3.3

LABEL maintainer="NSS-NDR"
LABEL description="Data bus for NSS-NDR (filebeat -> logstash -> redis -> logstash -> elasticsearch)"

# pipeline 配置
COPY images/logstash/logstash.yml /usr/share/logstash/config/logstash.yml
COPY images/logstash/pipelines.yml /usr/share/logstash/config/pipelines.yml
COPY images/logstash/pipelines/ /usr/share/logstash/pipelines/

# 证书目录（由 k8s Secret 挂载）
RUN mkdir -p /usr/share/logstash/certs && \
    chown -R 1000:1000 /usr/share/logstash/config /usr/share/logstash/pipelines /usr/share/logstash/certs
