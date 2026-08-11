#!/bin/sh
# 准备目录（单节点探针，/nsm 为共享数据卷；strelka 组件以 uid 939 运行）
set -e
mkdir -p /nsm/zeek/extracted/complete \
  /nsm/strelka/history /nsm/strelka/unprocessed \
  /nsm/strelka/staging /nsm/strelka/processed /nsm/strelka/log \
  /opt/so/log/strelka
chown -R 939:939 /nsm/strelka/history /nsm/strelka/unprocessed \
  /nsm/strelka/staging /nsm/strelka/processed /nsm/strelka/log
exec python3 /opt/so/conf/strelka/filecheck.py
