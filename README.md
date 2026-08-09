# NSS-NDR 流量探针

NDR 流量探针：Suricata（NIDS + 全包）+ Zeek（元数据）的容器化流量检测单元，部署在单节点 k3s，告警通过 Webhook 实时推送到主平台 XDR。

## 目录结构

```text
docs/                     # 设计文档（调研报告、架构设计）
images/
  suricata/               # Suricata 8.0.5 镜像（NIDS + pcap-log）
  zeek/                   # Zeek 8.0.8 镜像（元数据 + 文件提取）
deploy/k3s/               # k3s 清单（namespace/ConfigMap/PV/DaemonSet）
configs/                  # 探针配置文件示例（probe.yaml）
scripts/                  # 配置渲染等开发工具
```

## 当前状态

- [x] M0 骨架：引擎镜像 + k3s 清单 + 配置模板（本提交）
- [ ] M1：filebeat + elasticsearch + kibana 本地检索闭环
- [ ] M2：detections 规则管理 + xdr-push Webhook 推送
- [ ] M3：全包清理（cleaner）+ 文件提取 + Helm Chart

## 快速开始（M0）

```bash
# 1. 修改探针配置（接口/网段/阈值/XDR 地址等）
cp configs/probe.yaml.example configs/probe.yaml
$EDITOR configs/probe.yaml

# 2. 渲染 k3s 清单中的 ConfigMap
python3 scripts/render-configs.py configs/probe.yaml deploy/k3s/10-configmap.yaml

# 3. 部署到 k3s
kubectl apply -k deploy/k3s/
kubectl -n nss-ndr get pods
```

## 镜像构建（GitHub Actions）

- 推送 `master` 分支或 `v*` tag 时，`.github/workflows/build-images.yml` 自动构建 Suricata/Zeek 镜像并推送到 GHCR：
  - `ghcr.io/cxiyuan/nss-ndr-suricata:latest` / `:<git-sha>` / `:<tag>`
  - `ghcr.io/cxiyuan/nss-ndr-zeek:latest` / `:<git-sha>` / `:<tag>`
- 也可在 GitHub Actions 页面手动触发（workflow_dispatch）。
- 固定部署版本：把 `deploy/k3s/kustomization.yaml` 中 `images[].newTag` 改为对应 git sha。
- 前提：基础镜像 `ghcr.io/security-onion-solutions/so-suricata:3.1.0`、`so-zeek:3.1.0` 可被构建机拉取（public）。

### k3s 拉取 GHCR 镜像

GHCR 用户包默认**私有**，k3s 节点需要拉取凭据（DaemonSet 已引用 `imagePullSecrets: ghcr-pull`）：

```bash
# 在 k3s 节点上，用带 read:packages 权限的 PAT 创建 secret
kubectl -n nss-ndr create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=<你的 GitHub 用户名> \
  --docker-password=<PAT>
```

如需公开（跳过 secret），在 GitHub 网页打开对应 Package → Settings → Change visibility 设为 public，并删除
DaemonSet 中的 `imagePullSecrets`。

## 许可说明

- 设计参考 Security Onion 3.1.0（Elastic License 2.0）。本项目自研实现为主；
  若后续直接引入 SO 的 ingest pipeline/组件模板等资产，需按 ELv2 要求评估合规性（详见 `docs/架构设计-NDR探针-容器化-k3s.md` §10.2）。
- Suricata / Zeek 为 GPL-2.0 / BSD 系开源软件，按各自许可使用。
