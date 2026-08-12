#!/bin/sh
# NSS-NDR cleaner 入口
#
# 事故复盘（2026-08 部署机 IO 风暴）：cleaner 每小时对 /nsm（14GB+）做 du 扫描
# 与批量删除，与 elastic-agent 的 chown 叠加时加剧磁盘 IO 过载。
#
# 防护：以空闲 IO 优先级（ionice -c3）运行，扫描/删除不抢占采集与业务 IO。

set -e

if command -v ionice >/dev/null 2>&1; then
    exec ionice -c3 /usr/local/bin/cleaner "$@"
fi

exec /usr/local/bin/cleaner "$@"
