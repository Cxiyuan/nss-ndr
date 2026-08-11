# NSS-NDR Strelka YARA 规则编译器（initContainer 用）
# 构建期固定 securityonion-yara 提交；运行时把规则编译为 rules.compiled 输出到 /compiled

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir yara-python==4.5.1

ARG YARA_RULES_REF=ff1d898bc64bd7bd93203113a018fef78b64fc79
RUN git clone https://github.com/Security-Onion-Solutions/securityonion-yara.git /rules \
    && cd /rules && git checkout ${YARA_RULES_REF}

COPY files/compile_yara.py /usr/local/bin/compile_yara.py
ENTRYPOINT ["python3", "/usr/local/bin/compile_yara.py", "/rules", "/compiled"]
