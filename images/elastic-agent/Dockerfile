# NSS-NDR Elastic Agent 采集器（Fleet 托管模式，对齐 SO 3.1.0 的 elastic-agent）
# 基础镜像路径与 SO 一致：docker.elastic.co/elastic-agent/elastic-agent
# 容器模式（elastic-agent container）读取镜像默认 elastic-agent.yml，
# 配置/集成由 Fleet 策略下发；standalone agent.yml 已随 Fleet 化移除。

ARG VERSION=9.3.3

FROM docker.elastic.co/elastic-agent/elastic-agent:$VERSION

LABEL maintainer="NSS-NDR"
LABEL description="elastic-agent collector for NSS-NDR probe (Fleet-managed, aligned with Security Onion)"

USER root
