# NSS-NDR 边缘 AI 安全探针

> **一句话定位**：NDR 是一台部署在网络关键节点的**边缘自治 AI 探针**——它自己采集流量、自己生产告警线索、自己做结构化分析；只在需要深度推理时才把任务上下文**升级**给云端 XDR，由 XDR 接续分析并完成最终处置决策。

---

## 1. 设计意图（与 XDR 的关系）

```
┌─────────────────────────────────────────── NDR 边缘自治 AI 探针 ───────────────────────────────────────────┐
│                                                                                                              │
│   镜像口 ──┬──> suricata ──┐                                                                                │
│            │   (规则命中)    ├──> ES（suricata.alert + zeek.* + strelka.file）                                │
│            └──> zeek ───────┘   │                                                                          │
│                                ├──> xdr-push ──> XDR Webhook  ──> XDR 入库                                  │
│                                └──> 取证下载（pcap / 文件样本）                                              │
│                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**NDR 承担的职责（不是"数据生产侧"，而是"边缘自治 AI 探针"）**：

| 职责 | 实现 |
|---|---|
| **流量采集** | suricata（af-packet + pcap-log + eve.json）+ zeek（af-packet + JSON 协议日志 + 文件提取） |
| **告警生产** | suricata 规则命中 → `suricata.alert` 索引；同时完整落盘到 `/nsm/suripcap/*.pcap` |
| **元数据生产** | zeek 解析协议，输出 conn/dns/http/ssl/smb/ntlm/files 等十余种 `zeek.*` 数据流 |
| **本地存储** | Elasticsearch 9.3.3（xpack security）——所有线索 + 元数据 + Strelka 文件分析结果同库 |
| **线索推送** | xdr-push 把 Suricata 原始告警实时推送（游标 + HMAC + 死信）；XDR 接收后入库 |
| **取证下载** | pcap 全包下载（按文件名）+ 文件样本下载（按 MD5），受用户会话鉴权 |

**XDR 承担的职责（不在 NDR 范围内）**：

- 接收 NDR 推送的告警线索
- 最终威胁判断与处置（Sigma 关联、工单、响应）
- 跨探针聚合与安全数据可视化

---

## 2. 数据流（一次告警的完整生命周期）

1. **抓包**（suricata + zeek，hostNetwork + privileged）：af-packet 同镜像口，suricata cluster-id 59、zeek fanout 23，互不抢包
2. **落盘**：suricata eve.json（小时轮转）+ 全包 pcap（`so-pcap.<iso-ts>.<thread>.pcap`）；zeek JSON 日志（小时轮转）+ 提取文件 `<md5>.<ext>`
3. **采集**（standalone filebeat，直连 ES）：3 个 filestream 输入（suricata-eve / zeek-logs / strelka-logs），JS processor 生成稳定 `metadata._id`（避免重复入库） + 路由 `@metadata.pipeline`
4. **归一化**：ES ingest pipeline（81 个，对齐 Security Onion 3.1.0 字段映射）——ECS：`id.orig_h → source.ip`、`community_id → network.community_id`、`event.dataset = <engine>.<type`
5. **存储**：data stream（`logs-zeek-so` / `logs-suricata.alerts-so` / `logs-strelka-so`）+ ILM（hot→cold→delete）
6. **线索推送**：ndr-manager xdr-push goroutine 高频轮询 `logs-suricata.alerts-so`（默认 2s）→ 按 `event_types` 白名单（默认仅 `suricata.alert`）→ Webhook POST 给 XDR（HMAC-SHA256 签名 + 失败重试指数退避 + 死信落盘 + 游标断点续传）
7. **取证下载**：按需通过 Web UI 下载 pcap 全包或文件样本（MD5 检索 Strelka 扫描结果）

**数据本地性**：所有原始流量数据不出设备。出设备的只有告警线索（→ XDR webhook）和取证文件（按需下载）。

---

## 3. 架构组件

| 容器 | 角色 | 关键路径 |
|---|---|---|
| `suricata` | NIDS + pcap-log + eve.json | af-packet 镜像口，规则热加载 unix socket |
| `zeek` | 协议元数据 + 文件提取 | af-packet fanout，ICS×8/spicy×4/JA3/JA4/hassh |
| `filebeat` | 直连 ES 的 standalone 采集器 | 3 filestream + JS processor |
| `elasticsearch` | 单节点 + xpack security | 81 ingest pipeline + 3 索引模板 + 1 ILM |
| `ndr-manager` | 统一后台：配置 + 规则 + 推送 + cleaner + ES init + 取证下载 | Go + SQLite + 内嵌 React SPA |
| `strelka-*` | 文件静态分析（六组件：coordinator / gatekeeper / frontend / backend / filestream / manager / filecheck） | YARA/exiftool/PE/PDF，参照 SO 3.1.0 |

---

## 4. 目录结构

```text
docs/                              # 设计文档（架构设计 + 历史调研）
images/
  suricata/                        # Suricata 8.0.5 镜像（NIDS + pcap-log）
  zeek/                            # Zeek 8.0.8 镜像（元数据 + 文件提取）
  filebeat/                        # 直连 ES 的 standalone filebeat 配置
  ndr-manager/                     # 探针管理后台（配置/规则/线索推送/cleaner/ES init/取证下载）
  strelka-backend/                 # Strelka 扫描 worker（YARA/exiftool/PE/PDF...）
  strelka-manager/                 # Strelka frontend / filestream / manager / filecheck
  strelka-rules/                   # Strelka YARA 规则（构建期固化 securityonion-yara）
  es-init/                         # ES 初始化资产（81 ingest pipeline + ILM + 索引模板）
deploy/docker/                     # docker-compose 部署清单
configs/                           # 探针配置文件示例（probe.yaml.example）
releases/                          # 部署脚本 + 离线镜像包 + .run 自解压打包
test/                              # 端到端测试流量生成脚本
```

---

## 5. 快速开始

```bash
# 1. 准备探针配置
cp configs/probe.yaml.example configs/probe.yaml
$EDITOR configs/probe.yaml  # 必填：probe.interface（如 enp5s0），按需填写 XDR Webhook

# 2. 一键部署（自动：环境检测 / 网卡确认 / 渲染配置 / 生成 .env / 本地加载离线镜像 / docker compose up）
bash releases/deploy.sh install -i enp5s0
# 注意：镜像口 interface 是部署环境参数，必须按服务器实际网卡填写（空值会渲染失败）

# 3. 等待管理后台就绪（约 1-2 分钟），浏览器访问
# http://<本机IP>:30603  初始账号 admin / admin，登录后请改密

# 4. 离线部署：releases/images 存在时自动本地加载，不依赖网络拉取
cd deploy/docker && docker compose ps
```

### 发布包（.run 自解压，面向 Linux）

```bash
bash releases/package-release.sh --tag <版本>
# 产物：releases/nss-ndr-<版本>.run（Linux 上直接运行，离线镜像随包内置）

chmod +x nss-ndr-<版本>.run
./nss-ndr-<版本>.run install -i enp5s0      # 解压并部署
./nss-ndr-<版本>.run --dir /opt/nss-ndr     # 仅解压
./nss-ndr-<版本>.run --list                 # 查看包内容
```

---

## 6. 镜像构建（GitHub Actions）

- 推送 `master` 分支或 `v*` tag 时，`.github/workflows/build-images.yml` 自动构建并推送到 GHCR：
  - `ghcr.io/cxiyuan/nss-ndr/nss-ndr-suricata:latest` / `:<git-sha>` / `:<tag>`
  - `ghcr.io/cxiyuan/nss-ndr/nss-ndr-zeek:latest` / `:<git-sha>` / `:<tag>`
  - `ghcr.io/cxiyuan/nss-ndr/nss-ndr-ndr-manager`（内置 ES 初始化 / 线索上报 / 数据清理 / 取证下载）
  - `ghcr.io/cxiyuan/nss-ndr/nss-ndr-strelka-backend`、`strelka-manager`
- filebeat 使用官方镜像 `docker.elastic.co/beats/filebeat:9.3.3`（不构建）
- elasticsearch 使用官方镜像 `docker.elastic.co/elasticsearch/elasticsearch:9.3.3`
- 仓库 public，镜像自动继承 public 可见性
- 固定部署版本：`deploy.sh save-images --tag <git-sha>` 导出对应版本镜像包
- 基础镜像 `ghcr.io/security-onion-solutions/so-suricata:3.1.0`、`so-zeek:3.1.0`（public）

---

## 7. 部署前提

- 节点需设置 `vm.max_map_count=262144`（`sysctl -w vm.max_map_count=262144`，写入 `/etc/sysctl.d/99-nss-ndr.conf` 持久化）
- ES 已启用 xpack security：
  - `deploy.sh install` 自动生成 `deploy/docker/.env`（elastic 默认 `nss-ndr@2026`，其余随机）
  - ndr-manager 启动时自动初始化 ES（pipeline / 索引模板 / 应用用户 `filebeat` 与 `xdr-push`）
- ES 管理员：`elastic`，默认密码 `nss-ndr@2026`（仅内部使用）
- 离线环境：先用 `deploy.sh save-images` 导出镜像到 `releases/images/`，install 时会自动本地加载

---

## 8. 鉴权分层

| 接口 | 鉴权方式 | 用途 |
|---|---|---|
| `/api/login`、`/api/health` | 公开 | 登录、健康检查 |
| `/api/*` | `requireAuth` —— 用户会话（Bearer Token 或 cookie `ndr_session`） | 探针管理后台、配置、规则、监控、取证下载 |
| ndr-manager → XDR Webhook | HMAC-SHA256 签名（`XDR_WEBHOOK_SECRET`） | 告警线索推送 |

---

## 9. Web 后台（仅运维监控，不做安全数据可视化）

NDR Web 后台**只展示本探针自身的运维监控指标**，用于设备管理与运行状态查看：

- **Dashboard**：4 张数字卡（当日事件总量 / 告警线索量 / XDR 推送成功率 / 当前流量速率）+ 流量处理波形图（最近 60 分钟，SVG 折线，eps + bps 双轴）+ 告警线索分时柱状图 + 组件健康表 + 磁盘用量进度条 + Cleaner 状态 + dataset Top10 分布 + 探针基础信息。每 30s 自动刷新 + 手动刷新按钮
- **参数配置**：8 个 section（probe / suricata / zeek / elasticsearch / xdr / strelka / detections / resources）的 schema-driven 表单字段（49+ 个）+ YAML 高级模式 + 保存/下发
- **规则**：① 事件检测（ET Open ~3.9 万条 / 35 分类按需勾选启用 + 内置规则）+ ② 自定义规则（CRUD / 启停 / 阈值）+ 渲染并热加载 Suricata
- **历史与审计**：配置版本历史 + 审计日志

**不在 NDR Web 后台展示（划归 XDR）**：

- 具体告警的事件详情、五元组载荷、Suricata 规则匹配 payload
- 跨协议关联视图（community_id 时序、横向移动路径）
- Sigma 关联规则展示、攻击链时间线、IOC 检索
- 多探针联合视图、告警合并去重、研判工单

> **一句话总结**：NDR Web = "这台机器在干什么、干了多少"；XDR Web = "这些事件意味着什么、要不要处置"。

---

## 10. 许可说明

- 设计参考 Security Onion 3.1.0（Elastic License 2.0）。本项目自研实现为主；若后续直接引入 SO 的 ingest pipeline/组件模板等资产，需按 ELv2 要求评估合规性（详见 `docs/架构设计-NDR探针-容器化-k3s.md` §10.2）
- Strelka 组件：控制面 Go 程序来自 `target/strelka`（Apache-2.0），扫描器 Python 包来自 `defensivedepth/strelka` 分支（派生自 target/strelka）；YARA 规则来自 `Security-Onion-Solutions/securityonion-yara`。backend/frontend/filestream 等配置与镜像构建方式参照 SO 3.1.0（ELv2），仓库内已注明来源
- Suricata / Zeek 为 GPL-2.0 / BSD 系开源软件，按各自许可使用
