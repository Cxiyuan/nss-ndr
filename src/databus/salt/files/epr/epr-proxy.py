#!/usr/bin/env python3
# ============================================================================
# 微型 EPR（Elastic Package Registry）代理
# ----------------------------------------------------------------------------
# 目的：
#   Kibana Fleet 装包只认 registry（EPR）。公网 epr.elastic.co 的 zeek-5.0.1
#   只声明 43 个 dataset，缺本项目定制的 4 个（analyzer / postgresql /
#   quic / websocket）。而官方全量 distribution 镜像要 43.6GB，代价过高。
#
# 做法：
#   只写一个几十 KB 的小代理，绝大多数请求原样转发给公网 epr.elastic.co，
#   仅对 zeek 打两个补丁：
#     1) GET /search?package=zeek  → 在响应里给 zeek-5.0.1 补上 4 个
#        data_streams，并把 download 指向本服务的定制 zip
#     2) GET /epr/zeek-5.0.1.zip   → 返回本项目 47-dataset 的定制包
#   其它请求（/search 全量列表、/categories、fleet_server/elastic_agent 包
#   等）全部透传，Kibana 的其它功能不受影响。
#
# 依赖：python3 标准库（http.server + urllib），无需第三方包
# ============================================================================
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

UPSTREAM = os.environ.get("EPR_UPSTREAM", "https://epr.elastic.co")
PORT = int(os.environ.get("EPR_PORT", "8080"))
PKG_DIR = os.environ.get("EPR_PKG_DIR", "/opt/nss/ndr/epr")
ZEEK_PKG = os.environ.get("EPR_ZEEK_PACKAGE", "zeek-5.0.1")  # 形如 zeek-5.0.1
ZEEK_NAME, ZEEK_VERSION = ZEEK_PKG.rsplit("-", 1)

# 定制包相对上游新增的 dataset（本项目的 images/zeek-integration 里加了这些）
EXTRA_DS = [
    ("zeek.analyzer", "Zeek analyzer logs"),
    ("zeek.postgresql", "Zeek PostgreSQL logs"),
    ("zeek.quic", "Zeek QUIC logs"),
    ("zeek.websocket", "Zeek WebSocket logs"),
]

# Kibana 实际请求的下载路径是 /epr/{name}/{name}-{version}.zip
# （不是 search 响应里 download 字段的值），两个都支持以防万一
ZIP_PATH_CANON = "/epr/%s/%s.zip" % (ZEEK_NAME, ZEEK_PKG)
ZIP_PATHS = {ZIP_PATH_CANON, "/epr/%s.zip" % ZEEK_PKG}
ZIP_SIG_PATHS = {p + ".sig" for p in ZIP_PATHS}


def log(*a):
    print("[epr-proxy]", *a, flush=True)


def upstream_get(path, query):
    url = UPSTREAM + path + (("?" + query) if query else "")
    req = urllib.request.Request(url, headers={"User-Agent": "nss-ndr-epr-proxy/1.0"})
    return urllib.request.urlopen(req, timeout=60)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # 安静一点：只记录路径
    def log_message(self, fmt, *args):
        log("%s %s" % (self.command, self.path))

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_file(self, fpath, ctype):
        try:
            with open(fpath, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            log("缺文件: %s" % fpath)
            self._send(404, b'{"error":"not found"}')
            return
        self._send(200, data, ctype)

    def _patch_zeek_search(self, query):
        """转发 /search 并给 zeek 补上定制 dataset。"""
        with upstream_get("/search", query) as resp:
            data = json.loads(resp.read())
        patched = 0
        for p in data:
            if p.get("name") != ZEEK_NAME or p.get("version") != ZEEK_VERSION:
                continue
            have = {d.get("dataset") for d in p.get("data_streams", [])}
            for ds, title in EXTRA_DS:
                if ds not in have:
                    p.setdefault("data_streams", []).append(
                        {"type": "logs", "dataset": ds, "title": title}
                    )
                    patched += 1
            p["download"] = ZIP_PATH_CANON
            p["signature_path"] = ZIP_PATH_CANON + ".sig"
            break
        log("patch /search?%s -> zeek-%s data_streams +%d" % (query, ZEEK_VERSION, patched))
        return json.dumps(data).encode()

    def _proxy(self, path, query):
        """原样透传（含大响应，流式拷贝避免占内存）。"""
        try:
            resp = upstream_get(path, query)
        except urllib.error.HTTPError as e:
            # 上游 404 等：原样返回状态码
            self._send(e.code, e.read()[:4096])
            return
        except Exception as e:  # noqa: BLE001
            log("上游失败 %s: %r" % (path, e))
            self._send(502, b'{"error":"upstream error"}')
            return

        with resp:
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
            # 无 Content-Length + Connection: close → 客户端读到 EOF
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                shutil.copyfileobj(resp, self.wfile)
        self.close_connection = True

    def do_GET(self):
        parts = urlsplit(self.path)
        path, query = parts.path, parts.query

        # 1) 定制包本体（兼容 Kibana 实际请求的 /epr/<name>/<name>-<ver>.zip）
        if path in ZIP_PATHS:
            return self._serve_file(os.path.join(PKG_DIR, ZEEK_PKG + ".zip"), "application/zip")
        # 定制包签名（Kibana 不校验，给个空文件即可）
        if path in ZIP_SIG_PATHS:
            return self._send(200, b"", "application/octet-stream")

        # 2) 健康检查
        if path in ("/", "/health"):
            return self._send(200, b'{"status":"ok","proxy":true}')

        # 3) /search?package=zeek 打补丁
        qs = parse_qs(query)
        if path == "/search" and qs.get("package", [""])[0] == ZEEK_NAME:
            try:
                body = self._patch_zeek_search(query)
            except Exception as e:  # noqa: BLE001
                log("patch 失败: %r" % e)
                return self._send(502, b'{"error":"patch failed"}')
            return self._send(200, body)

        # 4) 其余透传
        return self._proxy(path, query)

    def do_HEAD(self):
        return self.do_GET()


def main():
    log("upstream=%s listen=0.0.0.0:%d pkg_dir=%s zeek=%s" % (UPSTREAM, PORT, PKG_DIR, ZEEK_PKG))
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
