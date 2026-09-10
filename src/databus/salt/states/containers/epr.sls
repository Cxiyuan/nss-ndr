# ============================================================================
# 本地 Elastic Package Registry（nss-ndr-epr）
# ----------------------------------------------------------------------------
# 为什么需要：
#   Kibana Fleet 默认从上游 epr.elastic.co 安装 zeek-5.0.1，该包只声明
#   43 个 dataset；本项目 images/zeek-integration/zeek-5.0.1 定制包声明 47 个
#   （+analyzer / postgresql / quic / websocket，zeek 8.x 新增）。
#   没有本地 EPR 时，fleet-setup 提交 47 streams 会 404：
#     "Stream template not found, unable to find dataset zeek.analyzer"
#
# 做法（不新建大镜像）：
#   - 直接用官方 distribution 镜像（~43GB，含全部官方包，Kibana 其它
#     包操作不受影响）；该镜像不适合推到 GHCR，故走 docker.elastic.co 直拉
#   - 从 elastic-agent-zeek 镜像抽出烘焙好的定制 zeek-5.0.1 包（47 dataset），
#     在宿主机打成 EPR 需要的 zip
#   - 用「单文件 bind 挂载」覆盖镜像内官方的 zeek-5.0.1.zip（+ 空 .sig）
#   - 以 -require-package-signatures=false 启动（定制包无官方签名）
#   - Kibana 侧 xpack.fleet.registryUrl=http://epr:8080
#     （configs.sls 下发 salt://databus/files/kibana/kibana.yml）
#
# 注意：
#   - EPR 启动后需 ~3 分钟索引 29903 个包才监听 8080（占 ~5.5GB 内存）
#     编排里用 wait-epr-ready 等待，不要 rely on 容器 up 即就绪
#   - zip 的目录结构必须是 <name>-<version>/...（zip 根为包目录）
# ============================================================================

{% from "databus/map.jinja" import databus with context %}

include:
  - databus.network
  - databus.volumes
  - databus.images

{% set cfg_root    = databus.get('config_root', '/opt/nss/ndr') %}
{% set epr_dir     = cfg_root ~ '/epr' %}
{% set epr         = databus.get('epr', {}) %}
{% set epr_image   = epr.get('image', 'docker.elastic.co/package-registry/distribution:9.5.2') %}
{% set epr_ip      = epr.get('ip', '192.168.250.70') %}
{% set pkg         = epr.get('zeek_package', 'zeek-5.0.1') %}
{% set agent_image = epr.get('source_agent_image', 'ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/elastic-agent-zeek:9.5.2') %}
{% set agent_repo  = agent_image.rsplit(':', 1)[0] %}

{% set epr_repo = epr_image.rsplit(':', 1)[0] %}
{% set epr_tag  = epr_image.rsplit(':', 1)[1] %}

# 注：EPR 镜像的拉取由 databus.images 统一处理（pillar databus:images 列表已含），
#     这里不再重复声明 docker_image，否则会“conflicting IDs”（SLS ID 全局唯一）。

# ---------- 目录 ----------
ensure-epr-dir:
  file.directory:
    - name: {{ epr_dir }}
    - makedirs: True
    - mode: "755"

# ---------- 从 elastic-agent-zeek 镜像抽出定制包并打 zip ----------
# 幂等：zip 存在且源镜像 ID 未变则跳过（.source-image-id 记录源镜像 digest）
build-zeek-package-zip:
  cmd.run:
    - name: |
        set -eu
        mkdir -p {{ epr_dir }}
        python3 - <<'PYEOF'
        import io, os, tarfile, zipfile, sys
        import docker

        epr_dir    = "{{ epr_dir }}"
        pkg        = "{{ pkg }}"
        agent_img  = "{{ agent_image }}"
        src_in_img = "/usr/share/elastic-agent/elastic-integrations/packages/" + pkg

        cli = docker.from_env()
        cid = cli.containers.create(agent_img)          # 不启动，只用于取文件
        try:
            stream, _ = cli.api.get_archive(cid.id, src_in_img)
            buf = io.BytesIO(b"".join(stream))
        finally:
            cid.remove(force=True)

        # 清掉旧目录后解包（tar 根条目即 pkg 目录）
        dst_root = epr_dir
        for name in (pkg,):
            p = os.path.join(dst_root, name)
            if os.path.isdir(p):
                import shutil
                shutil.rmtree(p)

        with tarfile.open(fileobj=buf) as tar:
            tar.extractall(dst_root)

        src = os.path.join(dst_root, pkg)
        out = os.path.join(dst_root, pkg + ".zip")
        n = 0
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(src):
                for f in files:
                    fp = os.path.join(root, f)
                    z.write(fp, os.path.relpath(fp, dst_root))
                    n += 1

        # 定制包无官方签名 → 放一个空 .sig（配合 -require-package-signatures=false）
        open(os.path.join(dst_root, pkg + ".zip.sig"), "w").close()

        # 记录源镜像 digest，供 unless 判断是否需要重建
        img_id = cli.images.get(agent_img).id
        with open(os.path.join(dst_root, ".source-image-id"), "w") as fh:
            fh.write(img_id + "\n")

        print("[epr] %s.zip 已生成（%d 个文件）" % (pkg, n))
        PYEOF
    - unless: |
        test -f {{ epr_dir }}/{{ pkg }}.zip &&
        test -f {{ epr_dir }}/.source-image-id &&
        [ "$(cat {{ epr_dir }}/.source-image-id)" = "$(python3 -c "import docker; print(docker.from_env().images.get('{{ agent_image }}').id)" 2>/dev/null)" ]
    - require:
      - docker_image: {{ agent_image }}
      - file: ensure-epr-dir

# ---------- EPR 容器 ----------
nss-ndr-epr:
  docker_container.running:
    - name: nss-ndr-epr
    - image: {{ epr_image }}
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    - binds:
        # 单文件覆盖官方 zeek 包（镜像内其余 29902 个官方包保持原样）
        - {{ epr_dir }}/{{ pkg }}.zip:/packages/package-storage/{{ pkg }}.zip:ro
        - {{ epr_dir }}/{{ pkg }}.zip.sig:/packages/package-storage/{{ pkg }}.zip.sig:ro
    - networks:
        - nss-net:
            - ipv4_address: {{ epr_ip }}
            - aliases:
                - epr
    - command:
        - -require-package-signatures=false
        - -address
        - 0.0.0.0:8080
    - log_driver: json-file
    - require:
      - docker_image: {{ epr_image }}
      - docker_network: ensure-nss-net-present
      - file: ensure-epr-dir
      - cmd: build-zeek-package-zip
