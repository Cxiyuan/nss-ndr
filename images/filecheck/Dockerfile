# NSS-NDR Strelka filecheck：把 Zeek 提取文件搬运到 Strelka 输入队列（去重）
# 参照 Security Onion 3.1.0 filecheck 行为（watchdog + SHA1 history 去重 + mv），
# 保留 SO 的 recycle 机制；history 清理改由脚本内定时线程完成（k8s 内无 cron）。

FROM python:3.11-slim

RUN pip install --no-cache-dir watchdog==6.0.0 pyyaml==6.0.2

COPY files/filecheck.py /opt/so/conf/strelka/filecheck.py
COPY files/filecheck.yaml /opt/so/conf/strelka/filecheck.yaml
COPY files/entrypoint.sh /usr/local/bin/filecheck-entrypoint.sh
RUN chmod +x /usr/local/bin/filecheck-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/filecheck-entrypoint.sh"]
