# NSS-NDR standalone filebeat：采集 Suricata/Zeek/Strelka 日志直连 ES（无 Kibana/Fleet/Logstash 依赖）
FROM docker.elastic.co/beats/filebeat:9.3.3

COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# filestream registry 需要可写
USER root
RUN mkdir -p /usr/share/filebeat/data && chown -R root:root /usr/share/filebeat/data
USER filebeat
