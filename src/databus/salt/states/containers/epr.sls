# ============================================================================
# 微型 EPR 容器（nss-ndr-epr）—— 给 Kibana Fleet 提供定制 zeek 包
# ----------------------------------------------------------------------------
# 背景：
#   Kibana Fleet 装包只认 registry（EPR）。公网 epr.elastic.co 的 zeek-5.0.1
#   只有 43 个 dataset；本项目 images/zeek-integration/zeek-5.0.1 定制包有 47 个
#   （+analyzer / postgresql / quic / websocket）。官方全量 distribution 镜像
#   要 43.6GB（含 29903 个包），代价过高。
#
# 做法：
#   - 跑 /opt/nss/ndr/epr/epr-proxy.py（由 configs.sls 下发，python 标准库实现）
#   - 该代理默认把请求转发给公网 epr.elastic.co，仅对 zeek 打补丁：
#       GET /search?package=zeek  → 给 zeek-5.0.1 补上 4 个 data_streams，
#                                    download 指向 /epr/zeek-5.0.1.zip
#       GET /epr/zeek-5.0.1.zip   → 返回定制 47-dataset 包
#   - 定制包 zip 在宿主机由 build-zeek-package-zip 生成：从 elastic-agent-zeek
#     镜像抽出烘焙好的 zeek-5.0.1 目录（minion 无 docker CLI，用 docker-py）
#   - Kibana 侧 xpack.fleet.registryUrl=http://epr:8080
#
# 镜像选择：
#   复用 salt 镜像（python:3.10-alpine 基座，服务器已有，零额外拉取）。
#   代理是纯标准库 Python 脚本，跑在哪个 python3 镜像里都一样；
#   服务器拉不动 docker.io 的 python:3.10-alpine（registry-1.docker.io 被重置），
#   故不为一个几十 KB 的脚本再引入一个镜像依赖。
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

include:
  - databus.network
  - databus.volumes
  - databus.images
  - databus.configs

{% set cfg_root    = databus.get('config_root', '/opt/nss/ndr') %}
{% set epr_dir     = cfg_root ~ '/epr' %}
{% set epr         = databus.get('epr', {}) %}
{% set epr_image   = epr.get('image', 'ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/salt:latest') %}
{% set epr_ip      = epr.get('ip', '192.168.250.70') %}
{% set pkg         = epr.get('zeek_package', 'zeek-5.0.1') %}
{% set agent_image = epr.get('source_agent_image', 'ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/elastic-agent-zeek:9.5.2') %}

# ---------- 目录 ----------
ensure-epr-dir:
  file.directory:
    - name: {{ epr_dir }}
    - makedirs: True
    - mode: "755"

# ---------- 从 elastic-agent-zeek 镜像抽出定制包并打 zip ----------
# 幂等：zip 存在且源镜像 digest 未变则跳过（.source-image-id 记录源镜像 ID）
build-zeek-package-zip:
  cmd.run:
    - name: |
        set -eu
        mkdir -p {{ epr_dir }}
        python3 - <<'PYEOF'
        import io, os, shutil, tarfile, zipfile
        import docker

        epr_dir   = "{{ epr_dir }}"
        pkg       = "{{ pkg }}"
        agent_img = "{{ agent_image }}"
        src_in_img = "/usr/share/elastic-agent/elastic-integrations/packages/" + pkg

        cli = docker.from_env()
        cid = cli.containers.create(agent_img)      # 不启动，只用于取文件
        try:
            stream, _ = cli.api.get_archive(cid.id, src_in_img)
            buf = io.BytesIO(b"".join(stream))
        finally:
            cid.remove(force=True)

        dst = os.path.join(epr_dir, pkg)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        with tarfile.open(fileobj=buf) as tar:
            tar.extractall(epr_dir)

        out = os.path.join(epr_dir, pkg + ".zip")
        n = 0
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(dst):
                for f in files:
                    fp = os.path.join(root, f)
                    z.write(fp, os.path.relpath(fp, epr_dir))
                    n += 1

        # 记录源镜像 ID，供 unless 判断是否需要重建
        with open(os.path.join(epr_dir, ".source-image-id"), "w") as fh:
            fh.write(cli.images.get(agent_img).id + "\n")
        print("[epr] %s.zip 已生成（%d 个文件）" % (pkg, n))
        PYEOF
    - unless: |
        test -f {{ epr_dir }}/{{ pkg }}.zip &&
        test -f {{ epr_dir }}/.source-image-id &&
        [ "$(cat {{ epr_dir }}/.source-image-id)" = "$(python3 -c "import docker; print(docker.from_env().images.get('{{ agent_image }}').id)" 2>/dev/null)" ]
    - require:
      - docker_image: {{ agent_image }}
      - file: ensure-epr-dir

# ---------- EPR 代理容器 ----------
nss-ndr-epr:
  docker_container.running:
    - name: nss-ndr-epr
    - image: {{ epr_image }}
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    - binds:
        # 只读挂载 epr 目录（含 epr-proxy.py + 定制 zip）
        - {{ epr_dir }}:/epr:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ epr_ip }}
            - aliases:
                - epr
    - environment:
        - EPR_PKG_DIR=/epr
        - EPR_PORT=8080
        - EPR_UPSTREAM=https://epr.elastic.co
        - EPR_ZEEK_PACKAGE={{ pkg }}
    - command:
        - python3
        - /epr/epr-proxy.py
    - log_driver: json-file
    - require:
      - docker_image: {{ epr_image }}
      - docker_network: ensure-nss-net-present
      - cmd: build-zeek-package-zip
      - file: {{ cfg_root }}/epr/epr-proxy.py
