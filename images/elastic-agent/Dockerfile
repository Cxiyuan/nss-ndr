# NSS-NDR Elastic Agent 采集器（standalone 模式，对齐 SO 3.1.0 的 elastic-agent）
# 与 SO 相同的 filestream 集成语义：zeek-logs / suricata-logs / strelka-logs，
# 输出 Lumberjack(TLS) 到 Logstash 5055；配置由 ConfigMap 覆盖。

FROM docker.elastic.co/beats/elastic-agent:9.3.3

LABEL maintainer="NSS-NDR"
LABEL description="elastic-agent collector for NSS-NDR probe (standalone, aligned with Security Onion)"

# 默认 standalone 配置（运行时由 ConfigMap 挂载覆盖）
COPY files/agent.yml /usr/share/elastic-agent/agent.yml

USER root
