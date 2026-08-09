# NSS-NDR filebeat 采集器（与 ES 同版本）

FROM docker.elastic.co/beats/filebeat:9.3.3

LABEL maintainer="NSS-NDR"
LABEL description="filebeat collector for NSS-NDR probe"

# 默认配置（运行时由 ConfigMap 挂载覆盖）
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

USER root
