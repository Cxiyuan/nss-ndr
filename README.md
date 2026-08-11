# NSS-NDR 流量探针

NDR 流量探针：Suricata（NIDS + 全包）+ Zeek（元数据）的容器化流量检测单元，部署在单节点 k3s，告警通过 Webhook 实时推送到主平台 XDR。

## 目录结构

```text
docs/                     # 设计文档（调研报告、架构设计）
images/
  suricata/               # Suricata 8.0.5 镜像（NIDS + pcap-log）
  zeek/                   # Zeek 8.0.8 镜像（元数据 + 文件提取）
  strelka-backend/        # Strelka 扫描 worker（YARA/exiftool/PE/PDF...，参照 SO）
  strelka-manager/        # Strelka frontend / filestream / manager（target/strelka Go）
  strelka-rules/          # YARA 规则编译（initContainer，securityonion-yara）
  filecheck/              # Zeek 提取文件搬运 + SHA1 去重（filecheck）
deploy/k3s/               # k3s 清单（namespace/ConfigMap/PV/DaemonSet）
configs/                  # 探针配置文件示例（probe.yaml）
scripts/                  # 配置渲染等开发工具
```

## 当前状态

- [x] M0 骨架：引擎镜像 + k3s 清单 + 配置模板（本提交）
- [x] M1：filebeat + elasticsearch + kibana 本地检索闭环（镜像/清单/管道就绪，待部署验证）
- [x] M2：detections 规则管理 + xdr-push Webhook 推送（镜像/清单就绪，待部署验证）
- [x] M3：cleaner 全包/日志清理 + 阈值/抑制 + ES 认证加固 + Helm Chart
- [x] M3b：文件提取 + Strelka（参照 SO 3.1.0：filecheck 搬运去重 + Strelka 六组件
  扫描集群 + strelka.file pipeline，k3s/Helm 双份清单就绪，待部署验证）

## 快速开始（M0）

```bash
# 1. 修改探针配置（接口/网段/阈值/XDR 地址等）
cp configs/probe.yaml.example configs/probe.yaml
$EDITOR configs/probe.yaml

# 2. 渲染 k3s 清单中的 ConfigMap
python3 scripts/render-configs.py configs/probe.yaml deploy/k3s/10-configmap.yaml
# 注意：10-configmap.yaml 为生成物不入库；镜像口(interface)为部署环境参数，
# 必须在本步骤前于 probe.yaml 中按服务器实际网卡填写（空值会渲染失败）

# 3. 部署到 k3s
kubectl apply -k deploy/k3s/
kubectl -n nss-ndr get pods
```

## Helm 部署

```bash
# 修改 deploy/helm/nss-ndr/values.yaml（探针配置/凭据）后：
helm upgrade --install nss deploy/helm/nss-ndr --namespace nss-ndr --create-namespace
```

> `deploy/helm/nss-ndr/configs/` 与 `images/*/files/` 保持同步，改引擎配置后运行
> `scripts/sync-helm-configs.sh`。

## 镜像构建（GitHub Actions）

- 推送 `master` 分支或 `v*` tag 时，`.github/workflows/build-images.yml` 自动构建 Suricata/Zeek 镜像并推送到 GHCR：
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-suricata:latest` / `:<git-sha>` / `:<tag>`
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-zeek:latest` / `:<git-sha>` / `:<tag>`
  - 另有 `nss-ndr-es-init`、`nss-ndr-filebeat`、`nss-ndr-kibana`（M1）
  - 另有 `nss-ndr-detections`、`nss-ndr-xdr-push`（M2）
  - 另有 `nss-ndr-strelka-backend`、`nss-ndr-strelka-manager`、`nss-ndr-strelka-rules`、
    `nss-ndr-filecheck`（文件提取 + Strelka）
- 也可在 GitHub Actions 页面手动触发（workflow_dispatch）。
- 固定部署版本：把 `deploy/k3s/kustomization.yaml` 中 `images[].newTag` 改为对应 git sha。
- 前提：基础镜像 `ghcr.io/security-onion-solutions/so-suricata:3.1.0`、`so-zeek:3.1.0` 可被构建机拉取（public）。

### 部署前提（ES）

- 节点需设置 `vm.max_map_count=262144`（`sysctl -w vm.max_map_count=262144`，写入 `/etc/sysctl.d/` 持久化）。
- M2/M3：ES 已启用 xpack security；部署前修改 `deploy/k3s/25-secret.yaml`（或 Helm
  `values.secrets`）中的 4 个密码，es-init 会自动创建 filebeat / kibana_system / xdr-push 应用用户。

### k3s 拉取 GHCR 镜像

镜像包已设为 **public**（workflow 自动设置），k3s 节点无需凭据即可拉取。若后续改回私有：

```bash
# 用带 read:packages 权限的 PAT 在 k3s 节点创建 secret
kubectl -n nss-ndr create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=<你的 GitHub 用户名> \
  --docker-password=<PAT>
```

## 许可说明

- 设计参考 Security Onion 3.1.0（Elastic License 2.0）。本项目自研实现为主；
  若后续直接引入 SO 的 ingest pipeline/组件模板等资产，需按 ELv2 要求评估合规性（详见 `docs/架构设计-NDR探针-容器化-k3s.md` §10.2）。
- Strelka 组件：控制面 Go 程序来自 `target/strelka`（Apache-2.0），扫描器 Python 包来自
  `defensivedepth/strelka` 分支（派生自 target/strelka）；YARA 规则来自
  `Security-Onion-Solutions/securityonion-yara`。backend/frontend/filestream 等配置与
  镜像构建方式参照 SO 3.1.0（ELv2），仓库内已注明来源。
- Suricata / Zeek 为 GPL-2.0 / BSD 系开源软件，按各自许可使用。
