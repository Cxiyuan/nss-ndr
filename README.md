# NSS-NDR 流量探针

NDR 流量探针：Suricata（NIDS + 全包）+ Zeek（元数据）的容器化流量检测单元，以 docker-compose 部署，检测线索通过 Webhook 实时推送到主平台 XDR。

## 目录结构

```text
docs/                     # 设计文档（调研报告、架构设计）
images/
  suricata/               # Suricata 8.0.5 镜像（NIDS + pcap-log）
  zeek/                   # Zeek 8.0.8 镜像（元数据 + 文件提取）
  filebeat/               # standalone filebeat（采集 Suricata/Zeek/Strelka 日志直连 ES）
  strelka-backend/        # Strelka 扫描 worker（YARA/exiftool/PE/PDF...，参照 SO）
  strelka-manager/        # Strelka frontend / filestream / manager（target/strelka Go）
  strelka-rules/          # YARA 规则编译（initContainer，securityonion-yara）
  ndr-manager/            # 探针管理后台（配置/规则/状态 + XDR 分析任务执行）
  strelka-manager/        # Strelka 控制面 + filecheck（文件搬运并入）
deploy/docker/            # docker-compose 部署（compose / .env.example）
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
- [x] M3c：Kibana NDR 看板（导出自 Security Onion 3.1.0，改名 NDR - * 并按本项目
  ES 模板修复 .keyword 字段；kibana-init sidecar 部署后自动导入 41 个看板/195 对象）
- [x] M8：采集层切换 Elastic Agent（对齐 SO filestream 集成语义：suricata/zeek/strelka
  三输入 + Logstash 输出；替代独立 filebeat）
- [x] M9：补齐 Fleet（对齐 SO）：Fleet Server + Fleet 托管 elastic-agent，
  fleet-init 自动供给输出/策略/filestream 集成/令牌/Secret；FleetServer 策略输出钉 ES、
  数据策略走 Logstash（与 SO 完全一致，basic license 可行）；41 个 NDR 看板随镜像发布
- [x] M10：suricata/zeek 插件与脚本对齐 SO 3.1.0：zeek local.zeek 全量加载清单（ICS/spicy/
  tds/profinet/http2/intel/cve-2020-0601/标准脚本集）+ config.zeek（JA4）；suricata 补
  so-suricata-testrule（单规则 pcap 验证）与 so-suricata-rulestats（规则统计，含 ndr-manager
  API /api/suricata/stats）

## 快速开始（M0）

```bash
# 1. 修改探针配置（接口/网段/阈值/XDR 地址等）
cp configs/probe.yaml.example configs/probe.yaml
$EDITOR configs/probe.yaml

# 2. 一键部署（渲染配置、生成 .env、本地加载离线镜像、docker compose up、等待就绪）
bash releases/deploy.sh install -i enp5s0
# 注意：镜像口(interface)为部署环境参数，必须按服务器实际网卡填写（空值会渲染失败）
# 离线部署：releases/images 存在时自动本地加载镜像，不依赖网络拉取
cd deploy/docker && docker compose ps
```

## docker compose 部署

```bash
# 启动：bash releases/deploy.sh install -i enp5s0
# 常用：cd deploy/docker && docker compose ps / logs -f suricata / down
```

配置渲染：`deploy.sh install` 自动渲染引擎配置到 `/opt/ndr/so/conf/`（suricata/zeek/filebeat/strelka），
凭据写入 `deploy/docker/.env`（gitignored）。

## 镜像构建（GitHub Actions）

- 推送 `master` 分支或 `v*` tag 时，`.github/workflows/build-images.yml` 自动构建 Suricata/Zeek 镜像并推送到 GHCR：
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-suricata:latest` / `:<git-sha>` / `:<tag>`
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-zeek:latest` / `:<git-sha>` / `:<tag>`
  - 另有 `nss-ndr-ndr-manager`（内置 ES 初始化 / 线索上报 / 数据清理）
  - 另有 `nss-ndr-strelka-backend`、`nss-ndr-strelka-manager`、`nss-ndr-strelka-rules`、
    （文件提取 + Strelka；filecheck 已并入 strelka-manager）
  - filebeat 使用官方镜像 `docker.elastic.co/beats/filebeat:9.3.3`（不构建）
- 也可在 GitHub Actions 页面手动触发（workflow_dispatch）。
- 固定部署版本：`deploy.sh save-images --tag <git-sha>` 导出对应版本镜像包。
- 前提：基础镜像 `ghcr.io/security-onion-solutions/so-suricata:3.1.0`、`so-zeek:3.1.0` 可被构建机拉取（public）。

### 部署前提（ES）

- 节点需设置 `vm.max_map_count=262144`（`sysctl -w vm.max_map_count=262144`，写入 `/etc/sysctl.d/` 持久化）。
- M2/M3：ES 已启用 xpack security；部署前生成凭据：
  - `deploy.sh install` 自动生成 `deploy/docker/.env`（elastic 默认 `nss-ndr@2026`，其余随机）
  - ndr-manager 启动时自动初始化 ES（pipeline/索引模板/应用用户 filebeat、xdr-push）。
- ES 管理员：`elastic`，默认密码 `nss-ndr@2026`（仅内部使用，不对用户开放）。

### 采集与上报（2026-08-15 架构）

```bash
# 一键部署（自动生成证书/凭据/ConfigMap 并 apply）
bash releases/deploy.sh install -i enp5s0
# 离线镜像：先在本机导出（需 skopeo）
bash releases/deploy.sh save-images
# 单步操作：render（渲染 ConfigMap）/ load-images（本地加载镜像）/ uninstall（卸载）
```

NDR 定位：采集 + 存储 + 上报线索 + 执行 XDR 下发的分析任务；XDR 为流程编排与决策平台。

1. **采集**：standalone filebeat（DaemonSet）读取 `/nsm` 下 Suricata eve、Zeek 日志、Strelka 结果，
   按文件名/事件类型映射 ingest pipeline，直连 ES 写入 data stream（无 Kibana/Fleet/Logstash 依赖）
2. **线索上报**：ndr-manager 内置任务定时把 `logs-suricata.alerts-so` 中的检测线索推送到 XDR Webhook
3. **分析任务**：XDR 通过 `POST /api/xdr/task`（Bearer 令牌）下发检索分析任务，
   NDR 作为执行者在本地元数据上完成关联分析并返回结构化结果（后台任务，不向探针用户展示）
4. **管理 UI**：仅设备管理（参数配置 / 规则启停 / 状态），不提供数据浏览
2. `fleet-server` 用 Secret 中的 service token 启动（容器必需 `FLEET_URL` 自注册 + `FLEET_CA` 信任）。
3. `elastic-agent` DaemonSet 用 enrollment token 接入（容器模式**必须 `FLEET_ENROLL=1`**，
   否则以 standalone 跑默认配置不注册；`FLEET_CA` 指向挂载的 CA 证书）。

### 拉取 GHCR 镜像

镜像包已设为 **public**（workflow 自动设置），部署节点无需凭据即可拉取；
离线环境用 `deploy.sh save-images` 导出、`deploy.sh load-images` 加载。

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
