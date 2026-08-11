#!/usr/bin/env python3
"""NSS-NDR 配置渲染：probe.yaml -> k3s ConfigMap

用法:
    python3 scripts/render-configs.py configs/probe.yaml deploy/k3s/10-configmap.yaml

依赖: pyyaml (pip3 install pyyaml)
"""

import math
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("缺少 pyyaml，请先安装：pip3 install pyyaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATES = {
    "suricata.yaml": "images/suricata/files/suricata.yaml",
    "threshold.conf": "images/suricata/files/threshold.conf",
    "local.zeek": "images/zeek/files/local.zeek",
    "node.cfg": "images/zeek/files/node.cfg",
    "zeekctl.cfg": "images/zeek/files/zeekctl.cfg",
    "networks.cfg": "images/zeek/files/networks.cfg",
}

STATIC_CONFIGS = {
    "kibana.yml": "images/kibana/kibana.yml",
    # Strelka 文件分析（参照 SO 3.1.0 配置，ELv2 资产见 README 许可说明）
    "strelka_backend.yaml": "images/strelka-backend/files/backend.yaml",
    "strelka_logging.yaml": "images/strelka-backend/files/logging.yaml",
    "strelka_passwords_dat": "images/strelka-backend/files/passwords.dat",
    "strelka_taste_yara": "images/strelka-backend/files/taste/taste.yara",
    "strelka_frontend.yaml": "images/strelka-manager/files/frontend.yaml",
    "strelka_filestream.yaml": "images/strelka-manager/files/filestream.yaml",
    "strelka_manager.yaml": "images/strelka-manager/files/manager.yaml",
}

POLICY_DIR = "images/zeek/files/policy/securityonion"


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def render_templates(ctx):
    data = {}
    for key, rel in TEMPLATES.items():
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            content = f.read()
        for k, v in ctx.items():
            content = content.replace("${" + k + "}", v)
        data[key] = content
    return data


def render_policy():
    data = {}
    base = os.path.join(ROOT, POLICY_DIR)
    for root, _dirs, files in os.walk(base):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), base)
            with open(os.path.join(root, name), encoding="utf-8") as f:
                # ConfigMap data key 不允许 "/"（仅 [-._a-zA-Z0-9]），
                # 用 "_" 扁平化；挂载时由 zeek DaemonSet volume items[].path 还原目录结构
                data[f"policy_securityonion_{rel.replace('/', '_')}"] = f.read()
    return data


def render_static():
    data = {}
    for key, rel in STATIC_CONFIGS.items():
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            data[key] = f.read()
    return data


def main():
    if len(sys.argv) != 3:
        print("用法: render-configs.py <probe.yaml> <out-configmap.yaml>")
        sys.exit(1)

    cfg_path, out_path = sys.argv[1], sys.argv[2]
    cfg = load_cfg(cfg_path)
    probe, suri, zeek = cfg["probe"], cfg["suricata"], cfg["zeek"]
    pcap = suri.get("pcap", {})

    if not probe.get("interface"):
        sys.exit("错误: probe.interface 未配置。镜像口是部署环境参数，请按服务器实际网卡填写（如 enp5s0）")
    if "CHANGE_ME" in probe.get("interface", "") or "占位" in probe.get("interface", ""):
        sys.exit("错误: probe.interface 仍是占位符，请填写实际镜像口网卡")

    threads = int(suri.get("af_packet_threads", 4))
    file_size_mb = int(pcap.get("file_size_mb", 1000))
    storage_gb = int(pcap.get("storage_limit_gb", 500))
    # 与 SO 一致的 max-files 计算：配额(GB*1000) / 单文件(MB) / worker 数
    max_files = max(1, math.ceil(storage_gb * 1000 / file_size_mb / threads))

    ctx = {
        "INTERFACE": probe["interface"],
        "THREADS": str(threads),
        # 与 SO 3.1.0 一致：地址序列用引号包裹，Suricata 8.0.5 要求
        "HOME_NET": "'[" + ",".join(probe["home_net"]) + "]'",
        "EXTERNAL_NET": str(probe.get("external_net", "any")),
        "PCAP_ENABLED": "yes" if pcap.get("enabled", True) else "no",
        "PCAP_FILE_SIZE_MB": str(file_size_mb),
        "PCAP_COMPRESSION": str(pcap.get("compression", "none")),
        "PCAP_MAX_FILES": str(max_files),
        "WORKERS": str(zeek.get("workers", 4)),
        "BUFFER_SIZE": str(zeek.get("buffer_size", "128*1024*1024")),
        "LOG_ROTATION_INTERVAL": str(zeek.get("log_rotation_interval_s", 3600)),
        "ZEEK_NETWORKS": "\n".join(
            f"{n} Private_IP_Space" for n in probe["home_net"]
        ),
    }

    data = render_templates(ctx)
    data.update(render_policy())
    data.update(render_static())
    data["bpf"] = probe.get("bpf", "")
    data["all-rulesets.rules"] = ""  # 默认空规则集
    data["sensor_id"] = probe["id"]
    data["interface"] = probe["interface"]
    data["probe.yaml"] = open(cfg_path, encoding="utf-8").read()

    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "nss-ndr-config", "namespace": "nss-ndr"},
        "data": data,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cm, f, sort_keys=False, allow_unicode=True)

    print(f"已生成 {out_path}（{len(data)} 个配置键）")
    print(f"  接口={ctx['INTERFACE']} 线程={threads} pcap_max_files={max_files}")


if __name__ == "__main__":
    main()
