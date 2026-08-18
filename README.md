# NSS-NDR 流量探针

NDR 流量探针：Suricata（NIDS + 全包）+ Zeek（元数据）的容器化流量检测单元，以 docker-compose 部署，检测线索通过 Webhook 实时推送到主平台 XDR。

## 项目定位（边界声明）

NDR 是**网络流量数据生产侧的探针单元**，定位与边界如下：

- **采集**：尽可能贴近数据生产侧，捕获并落盘尽可能完整的网络数据包（pcap 全包 + Zeek 元数据）
- **检测**：内置 Suricata 规则引擎做 NIDS 实时命中，ET Open 等内置规则库默认禁用、按分类加载
- **线索上报**：把检测命中（suricata.alert）按白名单实时 POST 到 XDR Webhook，HMAC 签名 + 重试 + 死信 + 游标断点
- **执行 XDR 下发的分析任务**：XDR 通过 `POST /api/xdr/task`（Bearer 令牌）下发检索/分析任务，NDR 在本地元数据上完成关联分析并返回结构化结果
- **LLM 噪声过滤（ndr-agent + mcp-server）**：本地小模型（Ollama OpenAI 兼容）+ MCP 工具集，对 XDR 下发的分析任务做推理与降噪，输出结论 + 证据链；未配置 LLM 时降级为结构化任务
- **本地 Web 后台（运维监控可视化）**：仅提供**本系统自身**的运维监控可视化（见下文），不提供安全数据分析可视化

### 本地 Web 后台提供的可视化范围

**NDR Web 后台只展示本探针自身的运维监控指标**，用于设备管理与运行状态查看：

- **流量处理波形图**：实时/历史抓包速率（pps / bps）时序曲线，反映当前流量负载
- **当日工作量统计**：当日事件总量、按 dataset 分布（zeek.conn / zeek.dns / ...）、当日告警线索量、Strelka 已处理文件数、XDR 推送成功/失败次数
- **系统健康**：各容器组件运行状态、ES 索引健康、磁盘用量、cleaner 状态、ES 队列堆积
- **配置 / 规则 / 历史审计**：参数配置、ET Open 规则启停、配置版本与审计日志

### 不在 NDR Web 后台提供（划归 XDR）

- **安全数据下钻**：具体告警的事件详情、五元组载荷、Suricata 规则匹配 payload 等
- **跨会话关联**：community_id 关联的多协议时序、横向移动路径还原
- **SOC / Hunt 视图**：Sigma 关联规则展示、攻击链时间线、IOC 检索
- **跨探针聚合**：多 NDR 联合视图、告警合并去重、研判工单

> 一句话总结：**NDR Web = 本探针运维监控（看"这台机器在干什么、干了多少"）；XDR Web = 安全数据研判（看"这些事件意味着什么、要不要处置"）**。

**明确不在 NDR 范围内（划归 XDR）**：

- **Sigma 规则库与关联规则编排**：Sigma 是 XDR 的关联分析与最终裁决手段，NDR 不内置、不维护、不调度
- **数据可视化（安全数据维度）/ 仪表盘 / 看板**：XDR 平台基于 NDR 提供的告警/元数据自行组织呈现
- **跨探针关联、工单、研判决策**：流程编排与决策由 XDR 完成，NDR 仅执行 XDR 下发的具体分析任务

## 目录结构

```text
docs/                     # 设计文档（架构设计 + 历史调研）
images/
  suricata/               # Suricata 8.0.5 镜像（NIDS + pcap-log）
  zeek/                   # Zeek 8.0.8 镜像（元数据 + 文件提取）
  filebeat/               # 直连 ES 的 standalone filebeat 配置（采集 Suricata/Zeek/Strelka）
                           # 注：M8 已完成 elastic-agent 切换，k3s 时期使用；
                           # docker-compose 部署仍以 filebeat 直连 ES 简化链路
  elastic-agent/          # （k3s 时期）Fleet 托管 elastic-agent 配置（M8/M9 引入）
  mcp-server/             # MCP Server（向本地 Agent 暴露分析工具集）
  ndr-agent/              # 本地分析 Agent（LLM + MCP 工具调用，做噪声过滤）
  ndr-manager/            # 探针管理后台（配置/规则/状态 + XDR 分析任务执行 + 线索推送 + cleaner + ES init）
  strelka-backend/        # Strelka 扫描 worker（YARA/exiftool/PE/PDF...，参照 SO）
  strelka-manager/        # Strelka frontend / filestream / manager + filecheck（文件搬运并入）
  strelka-rules/          # Strelka YARA 规则（构建期固化 securityonion-yara）
  es-init/                # ES 初始化资产（81 个 ingest pipeline + ILM + 索引模板）
deploy/docker/            # docker-compose 部署清单
configs/                  # 探针配置文件示例（probe.yaml.example）
releases/                 # 部署脚本 + 离线镜像包 + .run 自解压打包
test/                     # 端到端测试流量生成脚本
```

## 当前状态

- [x] M0 骨架：引擎镜像 + k3s 清单 + 配置模板（本提交）
- [x] M1：filebeat + elasticsearch 数据管道闭环（镜像/清单/ingest pipelines 就绪，
  待部署验证；数据可视化划归 XDR，本项目不内置 Kibana）
- [x] M2：detections 规则管理 + xdr-push Webhook 推送（镜像/清单就绪，待部署验证）
- [x] M3：cleaner 全包/日志清理 + 阈值/抑制 + ES 认证加固 + Helm Chart
- [x] M3b：文件提取 + Strelka（参照 SO 3.1.0：filecheck 搬运去重 + Strelka 六组件
  扫描集群 + strelka.file pipeline，k3s/Helm 双份清单就绪，待部署验证）
- [x] M8：采集层切换 Elastic Agent（k3s 时期；docker-compose 仍走 standalone filebeat 直连 ES，未启用）
- [x] M9：补齐 Fleet（对齐 SO）：Fleet Server + Fleet 托管 elastic-agent，
  fleet-init 自动供给输出/策略/filestream 集成/令牌/Secret；FleetServer 策略输出钉 ES、
  数据策略走 Logstash（与 SO 完全一致，basic license 可行）
- [x] M10：suricata/zeek 插件与脚本对齐 SO 3.1.0：zeek local.zeek 全量加载清单（ICS/spicy/
  tds/profinet/http2/intel/cve-2020-0601/标准脚本集）+ config.zeek（JA4）；suricata 补
  so-suricata-testrule（单规则 pcap 验证）与 so-suricata-rulestats（规则统计，含 ndr-manager
  API /api/suricata/stats）
- [x] M11：本地分析 Agent（ndr-agent + mcp-server）——LLM 小模型 + MCP 工具集，
  对 XDR 下发的分析任务做推理与噪声过滤，输出结构化结论与证据链
- [x] M12：本地 Web 运维监控可视化 —— Dashboard 页提供流量处理波形图、今日告警
  线索分时柱状图、当日事件分布、组件健康、磁盘用量、Cleaner 状态、XDR 推送统计；
  后端 4 个端点 `/api/monitoring/{traffic,workload,health,alerts-today}`，每 30s 自动刷新

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

### 发布包（.run 自解压，面向 Linux）

```bash
# 打包（部署脚本 + docker-compose + 离线镜像包 → 单个 .run 文件）
bash releases/package-release.sh --tag <版本>
# 产物：releases/nss-ndr-<版本>.run（Linux 上直接运行）

chmod +x nss-ndr-<版本>.run
./nss-ndr-<版本>.run install -i enp5s0      # 解压并部署（离线镜像随包内置，不拉网络）
./nss-ndr-<版本>.run --dir /opt/nss-ndr     # 仅解压
./nss-ndr-<版本>.run --list                 # 查看包内容
```

## 镜像构建（GitHub Actions）

- 推送 `master` 分支或 `v*` tag 时，`.github/workflows/build-images.yml` 自动构建 Suricata/Zeek 镜像并推送到 GHCR：
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-suricata:latest` / `:<git-sha>` / `:<tag>`
- `ghcr.io/cxiyuan/nss-ndr/nss-ndr-zeek:latest` / `:<git-sha>` / `:<tag>`
  - 另有 `nss-ndr-ndr-manager`（内置 ES 初始化 / 线索上报 / 数据清理）
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

NDR 定位：采集 + 存储 + 上报线索 + 执行 XDR 下发的分析任务（含 LLM 噪声过滤）；XDR 为流程编排与决策平台（含 Sigma 关联规则与可视化）。

1. **采集**：elastic-agent（Fleet 托管 DaemonSet，M8 起替代独立 filebeat）读取 `/nsm` 下
   Suricata eve、Zeek 日志、Strelka 结果，按文件名/事件类型映射 ingest pipeline，
   直连 ES 写入 data stream；docker-compose 部署可降级为 standalone filebeat 直连 ES（无可视化中间层依赖）
2. **线索上报**：ndr-manager 内置任务定时把 `logs-suricata.alerts-so` 中的检测线索推送到 XDR Webhook
3. **分析任务**：XDR 通过 `POST /api/xdr/task`（Bearer 令牌）下发检索分析任务，
   NDR 作为执行者在本地元数据上完成关联分析并返回结构化结果（后台任务，不向探针用户展示）
4. **LLM 噪声过滤**：XDR 通过 `POST /api/xdr/agent/task` 下发"是否为真实威胁"的研判任务，
   ndr-agent 通过 mcp-server 调用本地 ES 工具集，LLM 推理后给出结论与证据链
5. **管理 UI**：仅设备管理（参数配置 / 规则启停 / 状态），不提供数据浏览与可视化
6. `fleet-server` 用 Secret 中的 service token 启动（容器必需 `FLEET_URL` 自注册 + `FLEET_CA` 信任）。
7. `elastic-agent` DaemonSet 用 enrollment token 接入（容器模式**必须 `FLEET_ENROLL=1`**，
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
