#!/usr/bin/env python3
"""NSS-NDR Fleet 供给（对齐 SO so-elastic-fleet-setup，仅保留探针所需）

流程（全部幂等，可重复执行）：
  1. 等待 Kibana Fleet API 就绪
  2. 创建 ES service token（fleet-server 用）
  3. 创建 Fleet Server host（https://nss-fleet-server:8220）
  4. 创建 Logstash 输出（grid-logstash，hosts nss-logstash:5055，双向 TLS）
  5. 安装 filestream / fleet_server 包
  6. 创建 FleetServer 策略 + fleet_server 集成；创建 nss-ndr 策略 + 三个 filestream 集成
  7. 创建 nss-ndr enrollment token
  8. 写入 Secret（es_service_token / enrollment_token / ca_fingerprint）
"""

import base64
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

KIBANA = os.environ.get("KIBANA_URL", "http://nss-kibana:5601")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASSWORD", "")
NAMESPACE = os.environ.get("NAMESPACE", "nss-ndr")
SECRET_NAME = os.environ.get("SECRET_NAME", "nss-fleet-enrollment")
CERT_DIR = os.environ.get("CERT_DIR", "/etc/elastic-agent/certs")
CA_CRT = os.path.join(CERT_DIR, "ca.crt")
LOGSTASH_CRT = os.path.join(CERT_DIR, "elastic-agent.crt")
LOGSTASH_KEY = os.path.join(CERT_DIR, "elastic-agent.key")
POLICY_ID = os.environ.get("POLICY_ID", "nss-ndr")
FLEET_POLICY_ID = os.environ.get("FLEET_POLICY_ID", "FleetServer-nss")
INTEGRATIONS = os.environ.get("INTEGRATIONS_DIR", "/opt/fleet-init/integrations")

SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def k8s_ctx():
    ctx = ssl.create_default_context(cafile=SA_CA_PATH) if os.path.exists(SA_CA_PATH) else ssl._create_unverified_context()
    token = open(SA_TOKEN_PATH).read().strip() if os.path.exists(SA_TOKEN_PATH) else ""
    return ctx, token


def kib(path, method="GET", body=None, retry=3):
    req = urllib.request.Request(KIBANA + path, method=method)
    auth = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    req.add_header("Authorization", "Basic " + auth)
    req.add_header("kbn-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    if body is not None:
        req.data = json.dumps(body).encode()
    last = None
    for _ in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = r.read()
                return r.status, json.loads(data) if data else {}
        except urllib.error.HTTPError as e:
            data = e.read()
            try:
                last = (e.code, json.loads(data) if data else {})
            except Exception:
                last = (e.code, data[:200].decode(errors="ignore"))
            if e.code in (401, 403):
                return last
        except Exception as e:  # 网络未就绪
            last = (0, str(e))
        time.sleep(10)
    return last


def k8s_put_secret(data):
    ctx, token = k8s_ctx()
    url = f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/secrets/{SECRET_NAME}"
    body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": SECRET_NAME, "namespace": NAMESPACE},
        "type": "Opaque",
        "stringData": data,
    }
    # Secret 不存在时 PUT 返回 404，需先 POST 创建；已存在则 PUT 更新（幂等）
    for method in ("POST", "PUT"):
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode())
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if method == "POST" and e.code == 409:
                continue
            return e.code
    return 500


def ca_fingerprint():
    der = ssl.PEM_cert_to_DER_cert(open(CA_CRT).read())
    return hashlib.sha256(der).hexdigest().upper()


def ensure_exists(api, item_id, create_method, create_body):
    code, _ = kib(f"{api}/{item_id}")
    if code == 200:
        print(f"已存在 {api}/{item_id}，跳过")
        return
    code, resp = kib(api, create_method, create_body)
    print(f"创建 {api}/{item_id}: HTTP {code} {str(resp)[:120]}")


def main():
    # 1. 等待 Kibana Fleet API
    for _ in range(60):
        code, _ = kib("/api/fleet/agent_policies")
        if code == 200:
            break
        print("等待 Kibana Fleet API...")
        time.sleep(10)
    else:
        raise SystemExit("Kibana Fleet API 不可用")

    # 1.5 Fleet 一次性初始化（创建默认输出/预配置；缺 encryption key 时会 400）
    code, resp = kib("/api/fleet/setup", "POST", {})
    print(f"Fleet setup: HTTP {code} {str(resp)[:100]}")

    # 2. ES service token（fleet-server 认证 ES；9.x 由 Kibana 生成，无需 name）
    code, resp = kib("/api/fleet/service_tokens", "POST", {})
    es_token = resp.get("value", "")
    if not es_token:
        # 幂等：token 已存在则无法再取回，直接继续（fleet-server 用旧 token）
        print("WARN: 未能创建 ES service token，可能已存在（幂等续跑）")
    print("ES service token 就绪")

    # 3. Fleet Server host
    ensure_exists(
        "/api/fleet/fleet_server_hosts",
        "grid-default",
        "POST",
        {"id": "grid-default", "name": "grid-default", "is_default": True,
         "host_urls": ["https://nss-fleet-server:8220"]},
    )

    # 4. Logstash 输出（默认输出，双向 TLS）
    logstash_crt = open(LOGSTASH_CRT).read()
    logstash_key = open(LOGSTASH_KEY).read()
    logstash_ca = open(CA_CRT).read()
    output_body = {
        "id": "so-manager_logstash",
        "name": "grid-logstash",
        "type": "logstash",
        "hosts": ["nss-logstash:5055"],
        "is_default": True,
        "is_default_monitoring": True,
        "config_yaml": "",
        "ssl": {"certificate": logstash_crt, "certificate_authorities": [logstash_ca]},
        "secrets": {"ssl": {"key": logstash_key}},
        "proxy_id": None,
    }
    code, _ = kib("/api/fleet/outputs/so-manager_logstash")
    if code == 200:
        print("输出 so-manager_logstash 已存在，跳过")
    else:
        code, resp = kib("/api/fleet/outputs", "POST", output_body)
        print(f"创建 logstash 输出: HTTP {code} {str(resp)[:120]}")

    # 5. 安装包（GET 即使未安装也返回 200，需检查 status 才跳过）
    for pkg in ("filestream", "fleet_server"):
        code, resp = kib(f"/api/fleet/epm/packages/{pkg}")
        installed = resp.get("item", {}).get("status") == "installed" if code == 200 else False
        if not installed:
            code, resp = kib(f"/api/fleet/epm/packages/{pkg}", "POST", {"force": True})
            print(f"安装包 {pkg}: HTTP {code} {str(resp)[:100]}")
        else:
            print(f"包 {pkg} 已安装 v{resp.get('item', {}).get('version', '?')}")

    filestream_ver = "0.0.0"
    code, resp = kib("/api/fleet/epm/packages/filestream")
    if code == 200:
        filestream_ver = resp.get("item", {}).get("version", "0.0.0")
    fleet_server_ver = "0.0.0"
    code, resp = kib("/api/fleet/epm/packages/fleet_server")
    if code == 200:
        fleet_server_ver = resp.get("item", {}).get("version", "0.0.0")

    # 6. 策略
    for pid, name, desc in (
        (FLEET_POLICY_ID, "FleetServer-nss", "Fleet Server"),
        (POLICY_ID, "nss-ndr", "NDR probe"),
    ):
        code, _ = kib(f"/api/fleet/agent_policies/{pid}")
        if code == 200:
            print(f"策略 {pid} 已存在，跳过")
            continue
        code, resp = kib("/api/fleet/agent_policies", "POST",
                         {"id": pid, "name": name, "description": desc,
                          "namespace": "default", "monitoring_enabled": [],
                          "inactivity_timeout": 1209600, "is_protected": False})
        print(f"创建策略 {pid}: HTTP {code} {str(resp)[:100]}")

    # 7. 集成（package policies）
    code, resp = kib(f"/api/fleet/agent_policies/{POLICY_ID}")
    existing = [p.get("name") for p in resp.get("item", {}).get("package_policies", [])] if code == 200 else []
    for integ in ("fleet-server.json", "suricata-logs.json", "zeek-logs.json", "strelka-logs.json"):
        with open(os.path.join(INTEGRATIONS, integ)) as f:
            pp = json.load(f)
        name = pp.get("name")
        if name in existing:
            print(f"集成 {name} 已存在，跳过")
            continue
        pp["policy_id"] = FLEET_POLICY_ID if integ == "fleet-server.json" else POLICY_ID
        pp["package"]["version"] = fleet_server_ver if integ == "fleet-server.json" else filestream_ver
        code, resp = kib("/api/fleet/package_policies", "POST", pp)
        print(f"创建集成 {name}: HTTP {code} {str(resp)[:120]}")

    # 8. enrollment token
    code, resp = kib("/api/fleet/enrollment_api_keys", "POST", {"policy_id": POLICY_ID})
    enroll_token = resp.get("item", {}).get("api_key", "")
    if not enroll_token:
        # 幂等：已存在的 token 不可回读，从已有 key 列表里取
        code, resp = kib("/api/fleet/enrollment_api_keys")
        keys = resp.get("list", [])
        for k in keys:
            if k.get("policy_id") == POLICY_ID and k.get("active"):
                enroll_token = k.get("api_key", "")
                break
    print("enrollment token 就绪" if enroll_token else "WARN: 未取得 enrollment token")

    # 9. 写入 Secret
    secret_data = {
        "es_service_token": es_token,
        "enrollment_token": enroll_token,
        "ca_fingerprint": ca_fingerprint(),
    }
    code = k8s_put_secret(secret_data)
    print(f"写入 Secret {SECRET_NAME}: HTTP {code}")
    if code in (200, 201):
        print("Fleet 供给完成")
        return
    raise SystemExit("Secret 写入失败")


if __name__ == "__main__":
    while True:
        try:
            main()
            break
        except SystemExit as e:
            print(f"重试: {e}")
            time.sleep(30)
        except Exception as e:
            print(f"异常重试: {e}")
            time.sleep(30)
