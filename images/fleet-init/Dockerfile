# NSS-NDR Fleet 初始化器：Kibana/ES 就绪后自动供给 Fleet（对齐 SO so-elastic-fleet-setup）
# 创建 logstash 输出 / agent policy / filestream 集成 / enrollment token，
# 并把 es_service_token / enrollment_token / ca_fingerprint 写入 k8s Secret 供 fleet-server 与 agent 使用

FROM python:3.12-alpine

COPY files/fleet_provision.py /usr/local/bin/fleet_provision.py
COPY files/integrations/ /opt/fleet-init/integrations/

ENTRYPOINT ["python3", "/usr/local/bin/fleet_provision.py"]
