#!/usr/bin/env python3
"""
从 ghcr.io 下载镜像并打包成 docker-save 格式的 tar.gz（供 docker load）。

背景：服务器连 ghcr.io / nju 极慢且不稳定，镜像拉取基本不可用。
      改由网络正常的机器下载 → 分片 scp → 服务器 docker load。

注意：
  - 本机无需安装 docker，直接走 Registry HTTP API。
  - 输出格式用「经典 docker save 格式」而不是 OCI 布局：
    实测服务器 docker 26.1.3（overlay2 graphdriver）的 docker load
    不接受 OCI layout tar（报 blobs/json not found），经典格式正常。
  - 层 blob 从 registry 拿到的是 gzip，需要解压成 layer.tar 放进包里；
    整包再 gzip 一层，传输体积与 registry 压缩层相当。

用法：
  python3 scripts/fetch-image.py <ghcr仓库> <tag> <输出tar.gz> <引用名1> [引用名2 ...]

例：
  python3 scripts/fetch-image.py cxiyuan/nss-ndr-public/salt latest \
      docker/salt-latest.tar.gz \
      ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/salt:latest \
      ghcr.io/cxiyuan/nss-ndr-public/salt:latest
"""
import gzip
import hashlib
import json
import os
import shutil
import sys
import tarfile
import time
import urllib.request

REGISTRY = "https://ghcr.io"
ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def http(url, token=None, accept=None):
    h = {"User-Agent": "nss-ndr-fetch/1.0"}
    if token:
        h["Authorization"] = "Bearer " + token
    if accept:
        h["Accept"] = accept
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=180)


def get_token(repo):
    return json.load(http("%s/token?scope=repository:%s:pull&service=ghcr.io" % (REGISTRY, repo)))["token"]


def download_blob(repo, token, digest, dest, expected_size=None):
    if expected_size and os.path.exists(dest) and os.path.getsize(dest) == expected_size:
        return 0
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    n = 0
    with http("%s/v2/%s/blobs/%s" % (REGISTRY, repo, digest), token) as r, open(tmp, "wb") as fh:
        while True:
            c = r.read(1 << 16)
            if not c:
                break
            fh.write(c)
            n += len(c)
    os.replace(tmp, dest)
    return n


def main():
    repo, tag, out_tar = sys.argv[1], sys.argv[2], sys.argv[3]
    refs = sys.argv[4:] or ["%s:%s" % (repo, tag)]

    work = out_tar + ".d"
    shutil.rmtree(work, ignore_errors=True)
    blobdir = os.path.join(work, "_blobs")
    os.makedirs(blobdir, exist_ok=True)

    token = get_token(repo)
    print("[1/4] 取 manifest ...", flush=True)
    m = json.load(http("%s/v2/%s/manifests/%s" % (REGISTRY, repo, tag), token, ACCEPT))
    if "manifests" in m:  # manifest list → linux/amd64
        for x in m["manifests"]:
            p = x.get("platform", {})
            if p.get("architecture") == "amd64" and p.get("os") == "linux":
                m = json.load(http("%s/v2/%s/manifests/%s" % (REGISTRY, repo, x["digest"]), token, ACCEPT))
                break
        else:
            raise SystemExit("找不到 linux/amd64 manifest")

    cfg_digest = m["config"]["digest"]
    layers = m["layers"]
    total = m["config"]["size"] + sum(l["size"] for l in layers)
    print("      层数=%d registry 压缩总大小=%.1fMB" % (len(layers), total / 1048576))

    print("[2/4] 下载 blobs ...", flush=True)
    t0, done = time.time(), 0
    cfg_path = os.path.join(blobdir, "config")
    download_blob(repo, token, cfg_digest, cfg_path, m["config"]["size"])
    layer_paths = []
    for i, l in enumerate(layers, 1):
        p = os.path.join(blobdir, "layer%03d" % i)
        download_blob(repo, token, l["digest"], p, l["size"])
        layer_paths.append(p)
        done += l["size"]
        print("\r      %d/%d 层  %.1f/%.1fMB" % (i, len(layers), done / 1048576, total / 1048576), end="", flush=True)
    dt = time.time() - t0
    print("\n      用时 %.1fs (%.0f KB/s)" % (dt, done / 1024 / max(dt, 1)))

    print("[3/4] 解压层并构造 docker-save 目录 ...", flush=True)
    cfg = json.load(open(cfg_path))
    diff_ids = cfg.get("rootfs", {}).get("diff_ids", [])
    layer_dirs = []
    for i, lp in enumerate(layer_paths):
        raw = gzip.decompress(open(lp, "rb").read())
        h = hashlib.sha256(raw).hexdigest()
        expect = diff_ids[i].split(":", 1)[1] if i < len(diff_ids) else None
        if expect and expect != h:
            raise SystemExit("层 %d diff_id 不匹配: 期望 %s 实际 %s" % (i, expect[:16], h[:16]))
        d = os.path.join(work, h)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "layer.tar"), "wb") as fh:
            fh.write(raw)
        with open(os.path.join(d, "VERSION"), "w") as fh:
            fh.write("1.0")
        json.dump(
            {"id": h,
             "created": cfg.get("created", "1970-01-01T00:00:00Z"),
             "container_config": {"Cmd": ["/bin/sh -c #(nop) ADD file in /"]}},
            open(os.path.join(d, "json"), "w"))
        layer_dirs.append(h)

    cfg_hex = hashlib.sha256(open(cfg_path, "rb").read()).hexdigest()
    shutil.copyfile(cfg_path, os.path.join(work, cfg_hex + ".json"))
    json.dump(
        [{"Config": cfg_hex + ".json", "RepoTags": refs,
          "Layers": ["%s/layer.tar" % d for d in layer_dirs]}],
        open(os.path.join(work, "manifest.json"), "w"))
    repo_tag = {}
    for ref in refs:
        r, t = ref.rsplit(":", 1)
        repo_tag.setdefault(r, {})[t] = cfg_hex
    json.dump(repo_tag, open(os.path.join(work, "repositories"), "w"))
    shutil.rmtree(blobdir, ignore_errors=True)

    print("[4/4] 打包（gzip） ...", flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(out_tar)), exist_ok=True)
    with open(out_tar, "wb") as fh:
        gz = gzip.GzipFile(fileobj=fh, mode="wb", compresslevel=1)
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for name in ("manifest.json", "repositories", cfg_hex + ".json"):
                tf.add(os.path.join(work, name), arcname=name)
            for d in layer_dirs:
                tf.add(os.path.join(work, d), arcname=d)
        gz.close()
    shutil.rmtree(work, ignore_errors=True)
    print("      ✓ %s (%.1fMB)  refs=%s" % (out_tar, os.path.getsize(out_tar) / 1048576, refs))


if __name__ == "__main__":
    main()
