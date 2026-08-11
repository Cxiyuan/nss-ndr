# NSS-NDR Elastic Agent 采集器（Fleet 托管模式，对齐 SO 3.1.0 的 elastic-agent）
# 基础镜像路径与 SO 一致：docker.elastic.co/elastic-agent/elastic-agent

ARG VERSION=9.3.3

FROM docker.elastic.co/elastic-agent/elastic-agent:$VERSION

LABEL maintainer="NSS-NDR"
LABEL description="elastic-agent collector for NSS-NDR probe (standalone, aligned with Security Onion)"

# 默认 standalone 配置（运行时由 ConfigMap 挂载覆盖）
COPY files/agent.yml /usr/share/elastic-agent/agent.yml

USER root
