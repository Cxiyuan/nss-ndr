# NDR 探针架构设计（容器化 · 目标 k3s）

> 版本：v0.2（2026-08-15 重新校准定位）
> 关联文档：[调研报告-Security-Onion-3.1.0-suricata-zeek数据管道.md](调研报告-Security-Onion-3.1.0-suricata-zeek数据管道.md)（历史调研，不再作为现行设计依据）
> 本设计大量复用 SO 3.1.0 已验证的配置资产（详见 §7）。

---

## 1. 定位与范围

### 1.1 项目定位（边界声明）

本单元是 **NDR 网络流量探针**，定位为**网络流量数据生产侧的探针单元**，承担以下职责：

- **采集**：尽可能贴近数据生产侧，捕获并落盘尽可能完整的网络数据包（pcap 全包 + Zeek 元数据 + 文件提取）
- **检测**：内置 Suricata NIDS 实时命中（内置 + ET Open + 自定义规则）
- **线索上报**：把检测命中（suricata.alert）按白名单实时 POST 到 XDR Webhook
- **执行 XDR 下发的分析任务**：在本地元数据上完成检索 / 关联分析并返回结构化结果
- **LLM 噪声过滤**（ndr-agent + mcp-server）：本地小模型 + MCP 工具集，对 XDR 下发的"是否为真实威胁"类分析任务做推理降噪
- **本地 Web 后台**：仅设备管理（参数 / 规则 / 状态 / 历史审计）

### 1.2 明确不在 NDR 范围内（划归 XDR）

- **Sigma 规则库与关联规则编排**：Sigma 是 XDR 的关联分析与最终裁决手段，NDR 不内置、不维护、不调度
- **安全数据可视化 / SOC / Hunt / 跨会话关联 / 跨探针聚合 / 工单研判**：划归 XDR 平台

### 1.3 本地 Web 后台——运维监控可视化（不提供安全数据可视化）

NDR Web 后台**只展示本探针自身的运维监控指标**，用于设备管理与运行状态查看，**不展示具体告警事件的内容**：

| 类别 | 指标示例 | 数据来源 |
|---|---|---|
| **流量处理波形图** | 实时抓包速率（pps / bps）时序曲线 | Suricata / Zeek stats socket（如 `suricatasc iface-stats` / `zeekctl netstats`） |
| **当日工作量统计** | 当日事件总量、按 dataset 分布、当日告警线索量、Strelka 已处理文件数、XDR 推送成功/失败计数 | ES 聚合查询（`logs-zeek-so` / `logs-suricata.alerts-so` / `logs-strelka-so`）+ ndr-manager 本地游标计数 |
| **系统健康** | 各容器组件运行状态、ES 索引健康（黄/红）、磁盘用量、cleaner 状态、采集队列堆积 | ndr-manager 拉取 `docker compose ps` / ES `_cluster/health` / `df` / `du` |
| **配置 / 规则 / 审计** | 参数配置表单、ET Open 规则启停树、配置版本历史、操作审计日志 | ndr-manager SQLite |

**NDR Web 后台刻意不展示的内容**（划归 XDR）：

- 具体告警的事件详情、五元组载荷、Suricata 规则匹配 payload 明文
- 跨协议关联视图（community_id 时序、横向移动路径）
- Sigma 关联规则展示、攻击链时间线、IOC 检索
- 多探针联合视图、告警合并去重、研判工单

> 一句话总结：**NDR Web = 本探针运维监控（"这台机器在干什么、干了多少"）；XDR Web = 安全数据研判（"这些事件意味着什么、要不要处置"）**。

### 1.4 部署形态

- 每台探针 = 单节点 docker-compose（2026-08-16 起替代原 k3s）；基础设施不纳入开发范围
- 交付内容：容器镜像 + docker-compose 清单 + 配置文件 + 发布包脚本（`.run` 自解压）

## 2. 总体架构

```mermaid
flowchart LR
    subgraph NODE["探针节点（docker-compose 单机）"]
        TAP[("镜像口/TAP (hostNetwork)")]
        SUR["suricata<br/>NIDS + pcap-log"]
        ZK["zeek<br/>元数据 + 文件提取"]
        EVE[("/nsm/suricata/eve-*.json")]
        ZLOG[("/nsm/zeek/logs/current/*.log")]
        SURPCAP[("/nsm/suripcap/*.pcap")]
        EXTRACT[("/nsm/zeek/extracted/")]
        FB["elastic-agent<br/>(filestream + 管道路由)"]
        ES["elasticsearch<br/>单节点 + ingest pipelines"]
        MG["ndr-manager<br/>(配置 / 规则 / 线索推送 / cleaner / ES init)"]
        MCP["mcp-server<br/>(本地 ES 工具集)"]
        AG["ndr-agent<br/>(LLM 噪声过滤)"]
        STR["strelka-*<br/>(文件分析)"]
        CFG["ConfigMap / conf/<br/>探针配置<br/>(留存/阈值/XDR 地址等)"]

        TAP --> SUR & ZK
        SUR --> EVE
        SUR --> SURPCAP
        ZK --> ZLOG
        ZK --> EXTRACT
        EVE --> FB
        ZLOG --> FB
        ZK --> STR
        STR --> FB
        FB --> ES
        ES --> MG
        MG -. 规则文件/热加载 .-> SUR
        MG -. 推送告警 .-> XDR["主平台 XDR"]
        XDR -. "POST /api/xdr/task<br/>(Bearer 令牌)" .-> MG
        XDR -. "POST /api/xdr/agent/task" .-> MG
        MG --> AG
        AG <--> MCP
        MCP --> ES
        CFG -.-> MG & SUR & ZK
    end
```

- XDR 通过 `POST /api/xdr/task` 下发结构化检索任务 → MG 直接查询 ES 返回结果
- XDR 通过 `POST /api/xdr/agent/task` 下发"研判类"任务 → MG 转发到 AG（LLM）→ AG 通过 MCP 工具调 ES
- 数据可视化、跨探针关联、Sigma 编排均在 XDR 侧，NDR 不持有这些组件

## 3. 容器清单（一次交付）

| 容器 | 职责 | 运行方式 | 说明 |
|---|---|---|---|
| `suricata` | NIDS 检测 + eve.json + pcap-log 全包 | hostNetwork + privileged | 基于 SO 镜像瘦身，AF_PACKET 抓包 |
| `zeek` | 协议元数据 + 文件提取 | hostNetwork + privileged | 基于 SO 镜像瘦身，JSON 日志 |
| `elastic-agent` | 采集 eve/zeek/strelka 日志 → Logstash/ES | DaemonSet（Fleet 托管） | Fleet 策略下发 filestream 集成，`@metadata.pipeline` 路由（对齐 SO） |
| `fleet-server` | Fleet Server（agent 策略/令牌/输出下发） | Deployment（8220） | 对齐 SO Fleet 托管；fleet-init 自动供给 |
| `elasticsearch` | 本地元数据/告警存储 + ingest pipeline 归一化 | Deployment + LocalPV | 单节点，ILM 自动清理；数据可视化由 XDR 负责 |
| `ndr-manager` | 配置/规则/线索推送/cleaner/ES init 统一管理 | Deployment（30603） | 自研 Go + SQLite + 内嵌 React SPA |
| `mcp-server` | 向本地 Agent 暴露分析工具集（查询本地 ES） | Deployment | Python FastMCP，streamable HTTP |
| `ndr-agent` | LLM 小模型 + MCP 工具调用，对 XDR 任务做噪声过滤 | Deployment（8081） | OpenAI 兼容协议（Ollama），未配置模型时降级为结构化任务 |
| `strelka-*` | 文件静态分析（YARA/exiftool/PE/PDF...） | Deployment + Redis | 参照 SO 3.1.0 六组件 |

> 说明：xdr-push / detections / cleaner / es-init 四个原独立服务已全部并入 `ndr-manager`（统一后台）；
> 数据可视化（Kibana/仪表盘）划归 XDR，NDR 镜像与清单不再包含可视化组件；
> 告警推送仍由 `ndr-manager` 内部 goroutine 轮询 ES 实现（详见 §5.7）。

## 4. 数据管道设计

### 4.1 端到端流程

1. **抓包**：suricata 与 zeek 各自 AF_PACKET 抓镜像口流量（复用 SO：suricata `cluster-id 59 / cluster_flow / threads N`；zeek `af_packet_fanout_id 23 / FANOUT_HASH / lb_procs N`）。
2. **落盘**：
   - suricata：eve.json 按小时轮转 `/nsm/eve-%Y-%m-%d-%H:%M.json`；pcap-log `%n/so-pcap.%t`（1000MB/个，多文件，可 LZ4）。
   - zeek：JSON 协议日志 `/nsm/zeek/logs/current/*.log`；文件提取 `/nsm/zeek/extracted/complete/`。
   - 详细落盘设计见 §4.3。
3. **采集**：elastic-agent（Fleet 托管）监听 `/nsm/suricata/eve*.json`、`/nsm/zeek/logs/current/*.log` 与 `/nsm/strelka/log/strelka.log`；集成由 Fleet 策略下发（filestream），Zeek 按文件名 JS 设 `@metadata.pipeline=zeek.<logname>`；Suricata 固定 `suricata.common`；ICS 日志自动打 `ics` tag。Phase 0 起 Suricata 只采集 `event_type=alert` 的线索事件，stats/flow 等非告警 eve 事件在 agent 侧丢弃，eve-log 的 stats 输出默认关闭。
4. **归一化**：ES ingest pipeline（复用 SO 的 `zeek.*` / `suricata.*` / `strelka.file` / `common`），字段映射 ECS：`id.orig_h→source.ip`、`community_id→network.community_id`、`sensorname→observer.name`、`event.dataset=module.dataset` 等。
5. **存储**：数据流（沿用 SO 命名）：
   - `logs-zeek-so`（Zeek 全部日志，`event.dataset=zeek.conn/...`）
   - `logs-suricata.alerts-so`（Suricata 命中线索 signal，管道显式 `_index` 路由，`nss.detection.stage=clue`）
   - `logs-zeek.notice` 归入 `logs-zeek-so`（`event.dataset=zeek.notice`）
   - `logs-strelka-so`（文件分析，若启用）
   - `logs-soc-so`（探针自身服务日志）
   - ~~`logs-detections.alerts-*`~~：已下线。最终裁决由 XDR 完成，NDR 不维护 detections 数据流（仅生产 `suricata.alert` 线索）
6. **告警推送**：`ndr-manager` 内置 xdr-push goroutine 监听告警相关数据流（高频轮询游标，默认 2s），按推送白名单过滤后**实时主动 POST 到配置文件中维护的 Webhook URL**（XDR 侧以该 URL 接收）。默认白名单仅 `suricata.alert`（线索，标记 `nss.detection.stage=clue`）；最终裁决由 XDR 完成，不在 NDR 维护 detections.alerts 索引。如需外推 `zeek.notice` 等上下文事件，在 `xdr.event_types` 显式配置。

### 4.2 事件模型（ECS 子集，与 SO 一致）

| 字段 | 来源 | 示例 |
|---|---|---|
| `@timestamp` | 事件时间 | 2026-08-09T12:00:00Z |
| `event.dataset` | zeek/suricata 类型 | zeek.conn / suricata.alert |
| `event.module` | zeek/suricata/strelka/soc | zeek |
| `event.category/type` | 网络事件分类 | network / alert |
| `event.severity + severity_label` | 告警级别（common 管道分级） | 1-4 → low/high/critical |
| `source.ip/port`、`destination.ip/port` | 五元组 | 10.0.0.1:1234 → 10.0.0.2:80 |
| `network.transport/protocol` | tcp/udp + 应用协议 | tcp / http |
| `network.community_id` | 跨引擎关联主键 | 1:JzzocikZDis8ICy2xnNRDG6ZAK4= |
| `network.bytes/packets` | 流量统计 | 592 / 6 |
| `observer.name` | 探针标识（sensorname） | nss-001 |
| `rule.name/signature/uuid` | Suricata 规则命中 | GPL ATTACK_RESPONSE... |
| `log.id.uid` | zeek uid / suricata flow_id | CgD7r4R0yIirXqF0c |
| `related.ip` | 关联 IP 列表 | [10.0.0.1,10.0.0.2] |
| `host.name` | 探针主机名 | nss-001 |

### 4.3 日志与全包落盘设计（/nsm 布局）

#### 4.3.1 目录布局（数据盘 PV 挂载 /nsm）

```text
/nsm/                                        # 数据盘（LocalPV），所有流量数据落这里
├── suricata/
│   └── eve-2026-08-09-12:00.json            # eve.json 系列：按小时轮转，文件名带时间戳
├── zeek/
│   ├── logs/
│   │   ├── current/                         # 活跃日志：conn.log / dns.log / http.log / ssl.log ...
│   │   └── <rotated>/                       # 轮转历史（1h 一次，gzip 压缩，仅留档不采集）
│   ├── spool/                               # zeekctl spool（state.db、暂存）
│   └── extracted/
│       ├── <staging>/                       # 提取中的临时文件
│       └── complete/<md5>.<ext>             # 提取完成（md5 命名天然去重）
├── suripcap/                                # Suricata 全包（pcap-log）
│   ├── so-pcap.2026-08-09-12:00:00.1.pcap
│   └── so-pcap.2026-08-09-12:30:00.2.pcap
├── strelka/                                 # （可选）文件分析输入/输出
├── elasticsearch/                           # ES 数据目录（可独立 LocalPV，见 §4.3.3）
└── import/                                  # （可选）离线 pcap 导入
```

#### 4.3.2 引擎落盘行为表

| 数据 | 路径 | 轮转 | 压缩 | 采集方式 | 清理策略 |
|---|---|---|---|---|---|
| Suricata eve.json | `/nsm/suricata/eve-%Y-%m-%d-%H:%M.json` | 每小时（`rotate-interval: hour`） | 不压缩（采集器边读边走） | elastic-agent 匹配 `eve*.json`（含已轮转文件，排除 `.gz`） | 采集完成后按 `suricata.eve.retention_days`（默认 7）删除 |
| Suricata 运行日志 | 容器内 `/var/log/suricata/` | 容器日志滚动 | - | 不采集 | 随容器日志轮转 |
| Suricata 全包 | `/nsm/suripcap/so-pcap.%t` | 单文件 `limit=1000MB`、`mode: multi` 自动续写 | 可选 LZ4 | 不采集（供 XDR 按需拉取/取证） | **三层保险**：① Suricata `max-files` 自限制（第一道）；② cleaner 双阈值（天数+容量）；③ 磁盘压力兜底（见 §5.9） |
| Zeek 协议日志 | `/nsm/zeek/logs/current/*.log` | 每小时（`LogRotationInterval=3600`） | `CompressLogs=1` gzip 后移入历史目录 | elastic-agent 只 tail `current/*.log` | 历史目录按 `zeek.history_retention_days`（默认 30）清理 + 磁盘压力兜底 |
| Zeek 提取文件 | `/nsm/zeek/extracted/complete/<md5>.<ext>` | - | - | 不采集（交 Strelka 或留档） | 按 `zeek.extraction.max_days`（默认 7）清理 + 磁盘压力兜底 |
| Zeek 运行日志 | `/nsm/zeek/logs/current/{reporter,stats,stderr,stdout}.log` | 随轮转 | gzip | **排除**（elastic-agent exclude_files） | 随历史目录清理 |
| ES 索引数据 | `/nsm/elasticsearch/` | ILM rollover | - | - | ILM：hot→cold→delete（`metadata_days` 默认 60 / `alerts_days` 默认 365） |

#### 4.3.3 磁盘规划建议

- **容器化部署不依赖分区方案，按"挂载目录"监控**：
  - 本项目以容器 + k8s 清单交付，`/nsm`、ES 数据目录等均为 **LocalPV/hostPath 挂载目录**；底层文件系统由部署方提供（独立分区 / LVM / RAID / NFS，或根分区下的普通目录），探针不感知、不干预。
  - 空间监控/清理只认两个运行时指标（见下），与"是否独立分区"无关，因此 **ISO 安装时的分区规划在本项目不存在，也不需要**。
- **两类监控指标（cleaner 与状态页使用）**：
  - **目录级用量（执行配额）**：`du` 统计 `/nsm/suripcap`、`/nsm/zeek/logs`、`/nsm/zeek/extracted` 等目录实际占用 → 用于执行 `storage_limit_gb` 与按天清理。目录级统计对"根分区下子目录"同样有效。
  - **文件系统级容量（压力兜底）**：`df` 查看挂载点所在文件系统用量 → 用于 `disk_pressure_threshold`（90%）与 `min_free_gb` 兜底。注意：若 `/nsm` 只是根分区子目录，`df` 反映的是整个根分区（含系统/容器镜像），阈值需按整体评估。
- **挂载点规划（推荐，非强制）**：
  - `/nsm` 建议独立挂载（数据盘）：流量数据（eve/zeek/suripcap/extracted）IO 型负载，建议 SSD/高速盘。
  - `/nsm/elasticsearch` 建议独立挂载（索引盘），避免与流量 IO 争抢；容量按 `metadata_days + alerts_days` 估算。
  - 若部署方只给一块盘，则全部挂根分区子目录，探针逻辑不变，仅兜底阈值按整盘评估。
- **k3s 侧注意**：
  - LocalPV/hostPath 上声明的 `capacity` 仅用于展示，**不强制配额**；kubelet 的 nodefs 驱逐只清理容器/镜像层，**不会清理 `/nsm` 数据** → cleaner 是数据清理的唯一执行者，必须保证其运行。
  - cleaner/状态采集以 DaemonSet/CronJob + hostPath 挂载运行，容器内 `df`/`du` 直接看到宿主文件系统。
- **容量估算**（写入配置模板注释）：
  - 全包：受 `storage_limit_gb` 封顶，或在 `retention_days × 每日产生量` 中取先到者。
  - 元数据：经验值约 1-3 KB/事件 × 事件率（PPS）× 3600 × 24 × `metadata_days`；ES 膨胀系数约 1.1-1.3。
- **启动自检**：探针启动时检查 `suripcap` 剩余容量，低于 `probe.min_free_gb`（默认 20GB）时告警并触发一次清理。
- **磁盘压力兜底（借鉴 SO `zeek_clean`）**：无论留存阈值如何配置，cleaner 每次运行时若 `/nsm` 用量 > `probe.disk_pressure_threshold`（默认 90%），强制循环删除最旧文件（zeek 历史目录 → 提取文件 → 全包），直到用量回落到阈值以下；防止配置不当/异常流量导致盘满。

#### 4.3.4 配置项映射（对应 §6.1 探针配置文件）

| 配置项 | 默认值 | 作用对象 |
|---|---|---|
| `suricata.pcap.retention_days` | 7 | suripcap 按天清理 |
| `suricata.pcap.storage_limit_gb` | 500 | suripcap 总量上限 |
| `suricata.pcap.file_size_mb` | 1000 | pcap-log 单文件大小 |
| `suricata.pcap.compression` | none/lz4 | pcap-log 压缩 |
| `suricata.eve.retention_days` | 7 | eve.json 留档天数 |
| `zeek.log_rotation_interval_s` | 3600 | zeek 日志轮转周期 |
| `zeek.history_retention_days` | 30 | zeek 轮转历史留档天数 |
| `zeek.extraction.max_days` | 7 | 提取文件留档天数 |
| `elasticsearch.retention.metadata_days` | 60 | ES ILM（元数据） |
| `elasticsearch.retention.alerts_days` | 365 | ES ILM（告警） |
| `probe.min_free_gb` | 20 | 磁盘低水位告警/触发清理 |
| `probe.disk_pressure_threshold` | 90 | `/nsm` 用量百分比，超过触发强制清理（兜底） |
| `probe.cleanup_interval` | 1h | cleaner 扫描周期 |

## 5. 组件详细设计

### 5.1 suricata（NIDS + 全包）

- 镜像：基于 `so-suricata:3.1.0` 瘦身（去掉无关依赖），Suricata 8.0.5。
- 配置：`suricata.yaml` 由探针配置渲染（ConfigMap → /etc/suricata），关键项：
  - `af-packet`：interface=镜像口、cluster-id 59、cluster_flow、threads 按核数配。
  - `eve-log`：`community-id: true`、小时轮转、alert 记录 `payload_printable + packet`。
  - `pcap-log`：enabled（配置开关）、`limit` 单文件大小、`max-files`（由存储配额自动计算，Suricata 侧第一道自限制，参考 SO）、LZ4 压缩选项。
  - `HOME_NET/EXTERNAL_NET`、BPF（可选）、应用层协议开关。
- 规则：`/etc/suricata/rules/` 挂载规则目录（detections 服务写入），`suricatasc reload` 热加载。
- 默认规则：**空规则集**（用户要求，默认不带任何规则）。
- 工具：`so-suricata-testrule`（单条规则 + pcap 验证）。

### 5.2 zeek（元数据引擎）

- 镜像：基于 `so-zeek:3.1.0` 瘦身，Zeek 8.0.8。
- 复用 SO 资产：`json-logs`、`community-id-extended`、`conn-add-sensorname`、`bpfconf`、`file-extraction`（MIME 白名单）、`cve-2020-0601`、intel。
- `local.zeek` 加载清单与 SO 3.1.0 **完全一致**：标准脚本集（software/known-*/ssl/ssh/http 检测等）、
  ja3/ja4/hassh/oui-logging、intel、cve-2020-0601、ICS 插件（icsnpp-modbus/dnp3/bacnet/ethercat/enip/
  opcua-binary/bsap/s7comm）、spicy 插件（wireguard/stun/ipsec/openvpn）、tds/profinet/http2、
  detect-windows-shells 签名；另叠加自研 `json-logs`（ISO8601）与 `conn-add-sensorname`（探针标识）。
- JA4 选项 `config.zeek` 与 SO 一致（覆盖 ja4 包内配置：仅启用基础 JA4，JA4+ 系列按 FoxIO 许可关闭）。
- 运行：`node.cfg` 多 worker（fanout 23）、`zeekctl.cfg` 轮转 1h + 压缩。
- 文件提取：白名单可配，`FileExtract::default_limit` 9MB，输出 `/nsm/zeek/extracted/complete/<md5>.<ext>`。

### 5.3 elastic-agent（Fleet 托管）

- 与 ES 同版本（9.3.3，见 §10）。镜像直接用官方
  `docker.elastic.co/elastic-agent/elastic-agent:9.3.3`（SO 同款，不做 standalone 配置覆盖）。
- 形态：Fleet 托管。`fleet-init` Job 对齐 SO `so-elastic-fleet-setup` 供给：
  1. 创建 ES 输出 `grid-elasticsearch` 与 Logstash 输出 `so-manager_logstash`（5055，双向 TLS）；
  2. **ES 输出临时设为全局默认** → 创建 `fleet_server` 集成 → PUT 把 FleetServer 策略
     `data_output_id/monitoring_output_id` 钉到 ES（此刻等于默认，basic license 不拦）→
     Logstash 恢复为全局默认；
  3. 创建 `nss-ndr` 数据策略（`monitoring_enabled: ["logs"]`）+ suricata/zeek/strelka
     三个 filestream 集成，数据与 agent 监控均走 Logstash 输出。
- 集成语义（对齐 SO filestream）：suricata `eve*.json`、zeek `current/*.log`
  （dissect 文件名 → JS 设 `@metadata.pipeline=zeek.<logname>` → module/category → ICS tag）、
  strelka `strelka.log`。
- 容器运行要点（产品通用）：必须设 `FLEET_ENROLL=1`（否则以 standalone 跑镜像默认配置、
  不注册 Fleet）；`FLEET_CA` 指向挂载的 CA；**不得把卷挂到 `/usr/share/elastic-agent/data`**
  （官方镜像 `elastic-agent` 是指向 `data/elastic-agent-*/elastic-agent` 的软链，
  挂空目录会 127 启动失败）。

### 5.4 elasticsearch

- 单节点、单副本 0、ILM：hot rollover → cold 60d（可配）→ delete（可配）。
- 启动时导入 ingest pipelines（从镜像内 assets 目录或 initContainer 加载 SO 的 pipeline JSON）与组件模板（ECS、DTC、so-* mappings）。
- 认证：本地自签 CA + 内置用户（filebeat/detections/xdr-push 各一）。
- 资源：heap 默认 1-2GB（可配）；数据目录 LocalPV。

### 5.5 Suricata 规则管理（ndr-manager 内置）

- **存储**：规则文件（`/opt/so/rules/suricata/all-rulesets.rules`，由 ndr-manager 渲染生成）+ SQLite 元数据表（`rules` 表，`type ∈ {custom, builtin, etopen}`）。
- **规则来源**：
  - `custom` — 用户/管理员通过 Web UI 新增的单条规则
  - `builtin` — 镜像内置规则集（`so_filters.rules` / `so_extraction.rules`，默认禁用，仅启停）
  - `etopen` — Emerging Threats Open 内置规则包（35 分类，约 3.9 万条，默认全部禁用，按分类勾选启用）
- **API**：
  - 规则 CRUD（仅 custom 可编辑/删除；builtin/etopen 仅可启停）
  - 阈值/抑制（规则内嵌 `threshold` 关键字，热加载即生效）
  - 分类树批量启停（ET Open）
  - 规则下发 → 渲染 `all-rulesets.rules` → 通过 unix socket 触发 suricata 热加载
  - 规则统计：`GET /api/suricata/stats`（对齐 SO `so-suricata-rulestats`）
- **UI**：Web UI 的"事件检测"页（ET Open 分类树）+ "自定义规则"页（CRUD），中文规则描述自动翻译。
- **不再涉及 Sigma**：Sigma 规则及其关联规则编排由 XDR 平台承担，NDR 仅生产线索（suricata.alert），不做最终裁决。

> 历史说明：M2 时期存在独立 `detections` 服务（API + 轻量 UI）+ `logs-detections.*` 索引。2026-08-15 起并入 `ndr-manager`，Sigma 相关能力（`logs-detections.alerts-so` 数据流、pySigma 转换器、调度器、证据预览 API）下线，由 XDR 平台替代。

### 5.7 线索推送（ndr-manager 内置 xdr-push goroutine）

- 输入：高频轮询 ES（`search_after`，默认 `push_interval_s=2`，可配）`logs-suricata.alerts-so` + `zeek.notice` 新文档；用文档 `_id` 做游标与去重（`metadata._id` 幂等）。
- 转换：ES 文档 → Webhook 告警报文（见 §5.8 报文规范），字段裁剪 + 枚举映射 + 探针标识。
- 输出：**Webhook**——配置文件中维护 `xdr.webhook.url` 变量；每产生一条新告警即主动 POST（实时推送），不依赖 XDR 轮询。
- 可靠性：
  - 本地持久化游标（PV），探针重启断点续传，不重复推送已确认文档。
  - 失败重试（指数退避 + 上限），超时重试，超限进入死信（本地 `state/xdr-push-dlq.jsonl`）。
  - 报文含 `alert_id`（ES 文档 `_id`）作为幂等键，XDR 可据此去重。
  - 可选 HMAC-SHA256 签名头（`xdr.webhook.secret` 配置，未配置则不签名）。
- 配置：Webhook URL/Secret/超时/重试/推送间隔/推送白名单。
  - **默认白名单仅 `suricata.alert`**（线索，标记 `nss.detection.stage=clue`）
  - 最终裁决由 XDR 完成，NDR 不再维护 `logs-detections.alerts-so` 索引
  - 如需外推 `zeek.notice` 等上下文事件，在 `xdr.event_types` 显式配置

### 5.8 Webhook 告警报文规范（v1 草案，供 XDR 侧对接）

```json
{
  "schema_version": "1.0",
  "probe_id": "nss-001",
  "alert_id": "es-document-_id",
  "timestamp": "2026-08-09T12:00:00.000Z",
  "source_type": "suricata.alert",
  "event": {
    "kind": "alert",
    "category": ["network"],
    "type": ["intrusion_detection"],
    "severity": 1,
    "severity_label": "low",
    "module": "suricata",
    "dataset": "suricata.alert"
  },
  "rule": {
    "name": "ET MALWARE ...",
    "signature": "alert tcp $HOME_NET any -> $EXTERNAL_NET any ...",
    "uuid": "2024211",
    "category": "attempted-user-admin",
    "reference": "url,https://...",
    "rev": 5
  },
  "source": { "ip": "10.0.0.1", "port": 52341, "mac": "00:0c:29:..." },
  "destination": { "ip": "8.8.8.8", "port": 443, "mac": "..." },
  "network": {
    "transport": "tcp",
    "protocol": "tls",
    "community_id": "1:JzzocikZDis8ICy2xnNRDG6ZAK4=",
    "bytes": 1234,
    "packets": 12
  },
  "observer": { "name": "nss-001", "hostname": "nss-001", "interface": "bond0" },
  "pcap": { "file": "so-pcap.2026-08-09-12:00:00.1.pcap", "offset_hint": "" },
  "raw": { "payload_printable": "", "base64": "" }
}
```

- 投递语义：`POST {url}`，`Content-Type: application/json`；2xx 视为成功；其余状态码/超时进入重试。
- 安全：可选 `X-NDR-Signature: sha256=hex(hmac_sha256(secret, body))`，XDR 可校验来源。
- `pcap.file`：全包已落盘时的文件引用，XDR 可按需通过探针 API 拉取（后续能力）。

### 5.9 本地分析 Agent（LLM 噪声过滤）

**定位**：XDR 下发的"是否为真实威胁 / 是否为噪声 / 风险等级如何"类研判任务，由 NDR 端的本地小模型 + MCP 工具集完成推理，最终结论回到 XDR 用于流程编排。

**调用链**：

```
XDR ──POST /api/xdr/agent/task (Bearer)──► ndr-manager
                                              │ (转发)
                                              ▼
                                        ndr-agent (FastAPI:8081)
                                              │  (MCP streamable HTTP)
                                              ▼
                                        mcp-server (MCP:8000)
                                              │  (查询)
                                              ▼
                                        elasticsearch (本地)
```

**MCP 工具集**（`mcp-server` 暴露）：

| 工具 | 用途 | 关键参数 |
|---|---|---|
| `list_datasets` | 列出可分析的元数据集 | — |
| `query_metadata` | 按目标（community_id/src_ip/dst_ip/uid）+ 时间窗检索指定数据集 | target / datasets / window_seconds / conditions |
| `correlate_session` | 按 community_id 拉取会话全链路元数据 | community_id / window_seconds |
| `aggregate_stats` | 按目标 + 时间窗做 top-N 聚合 | target / window_seconds / field / top_n |
| `get_clue` | 检索 Suricata 告警线索（`logs-suricata.alerts-so`） | target / window_seconds |
| `query_files` | 查询文件分析结果（`logs-strelka-so`） | mime_type / md5 / window_seconds |

**Agent 工作模式**（`ndr-agent`）：

1. **LLM 模式**（默认，`LLM_MODEL` 非空）：
   - OpenAI 兼容协议调 Ollama（`http://host.docker.internal:11434/v1/chat/completions`）
   - 工具调用循环：LLM 收到任务 + 工具列表 → 自主选工具 → MCP 调用 → 把工具结果回灌 LLM → 直至 LLM 给出结论
   - 上限 `MAX_STEPS=6` 步防死循环
   - 输出：`{ ok, conclusion, llm_used, llm_model, evidence:[{tool, args, result}] }`
2. **结构化降级**（`LLM_MODEL` 留空）：
   - 直接调 `query_metadata` / `correlate_session` 等工具汇总
   - 适用于 XDR 下发的 target + datasets 明确的任务

**数据本地性**：

- mcp-server 与 ES 同机部署，**所有查询均走本地 ES，数据不出 NDR**
- 任务执行结果（结论 + 证据链）仅通过 HTTP 返回给 XDR，不持久化到 ES

**配置**：

- `xdr.agent_enabled`（默认 `true`）：是否启用 Agent 模式入口
- `xdr.agent_url`（默认 `http://nss-ndr-agent:8081/analyze`）：Agent HTTP 地址
- `xdr.task_token`：Bearer 令牌，XDR 调用本探针任务接口的认证凭据（与分析任务共享）

**辅助：结构化分析任务入口**（`POST /api/xdr/task`）

- 适用于不需 LLM 推理、目标明确（target/datasets/window_seconds）的检索任务
- NDR 直接查 ES 返回结构化结果，不经 LLM
- 与 Agent 入口共用 Bearer 令牌

### 5.10 cleaner（数据清理任务，ndr-manager 内置 goroutine）

- 职责：统一清理**磁盘原始文件**（防止流量盘写满），与 ES 侧 ILM（清理索引，防止索引盘写满）配套，两层互不替代。
- 运行形态：ndr-manager 内部 goroutine，按 `probe.cleanup_interval` 周期执行；以 hostPath 挂载 `/nsm` 运行；容器内直接 `df`（文件系统级容量）与 `du`（目录级用量），不依赖部署方分区方案（见 §4.3.3）。
- 磁盘状态上报：每次运行将各挂载点/目录用量（`df -P`、`du -sb`）、剩余空间、触发动作写入 `/opt/so/state/cleaner-status.json`，供运维查看与 XDR 侧探针状态查询。
- 清理对象与规则（全部来自探针配置文件）：
  - `/nsm/suripcap/`：按 `suricata.pcap.retention_days`（天数）与 `suricata.pcap.storage_limit_gb`（目录总量上限）**双阈值**，先按天、再按总量删除最旧文件（取先到者）。
  - `/nsm/suricata/eve-*.json`：按 `suricata.eve.retention_days`（默认 7 天）删除已轮转且已被 elastic-agent 采集的旧文件。
  - `/nsm/zeek/logs/<rotated>/`：按 `zeek.history_retention_days`（默认 30 天）删除轮转历史（gz）。
  - `/nsm/zeek/extracted/`：按 `zeek.extraction.max_days`（默认 7 天）删除提取文件。
  - `/nsm/strelka/processed/`、`/nsm/strelka/log/`：按 `strelka.retention.processed_days` / `log_days`（启用 Strelka 时生效）。
- 逻辑：分两级：
  1. **常规清理**：按留存天数/容量阈值删除过期文件（eve 旧文件、zeek 历史目录、提取文件、超阈值全包）。
  2. **磁盘压力兜底**：若 `/nsm` 用量 > `probe.disk_pressure_threshold`（默认 90%），循环删除最旧文件（顺序：zeek 历史 → 提取 → strelka 已扫描 → 全包），直到用量回落（借鉴 SO `zeek_clean` 机制）。
- 低水位保护：每次清理后校验 `/nsm` 剩余空间，仍低于 `probe.min_free_gb`（默认 20GB）时向本地日志告警。

## 6. 配置管理

### 6.1 探针统一配置文件（YAML，ConfigMap 挂载）

```yaml
probe:
  id: nss-001                 # 探针唯一标识（observer.name / 推送标记）
  interface: ""               # 镜像口：部署时按服务器实际网卡填写（如 enp5s0），不固化默认值
  home_net:                   # HOME_NET 地址组
    - 10.0.0.0/8
    - 192.168.0.0/16
  bpf: ""                     # 可选 BPF
suricata:
  enabled: true
  af_packet_threads: 4
  pcap:
    enabled: true
    file_size_mb: 1000
    compression: lz4
    retention_days: 7
    storage_limit_gb: 500
zeek:
  enabled: true
  workers: 4
  file_extraction:
    enabled: true
    mime_whitelist: [application/pdf, application/x-dosexec, ...]
elasticsearch:
  heap_gb: 2
  retention:
    metadata_days: 60
    alerts_days: 365
xdr:
  webhook:
    url: https://xdr.example.com/api/v1/alerts/webhook   # XDR 接收地址（配置文件维护，可改）
    secret: ""                                            # 可选 HMAC 签名密钥
  task_token: ""                                          # XDR 调本探针任务接口的 Bearer 令牌
  agent_enabled: true                                     # 启用本地分析 Agent（LLM 噪声过滤）
  agent_url: http://nss-ndr-agent:8081/analyze           # 本地 Agent 地址
  timeout_s: 10
  push_interval_s: 2
  retry_max: 5
  event_types: [suricata.alert]   # 推送白名单：默认仅推 suricata 线索；最终裁决由 XDR 完成
```

- 变更策略：ConfigMap 更新 → 相关容器 watch 或重启（k3s 天然支持）；后续可演进为 CRD。
- 敏感项（token/密码）用 k8s Secret。

## 7. 复用 SO 3.1.0 资产清单（核心策略：不造轮子）

| SO 资产 | 复用方式 | 用途 |
|---|---|---|
| `salt/elasticsearch/files/ingest/*.json`（2080 个） | 打包进 ES 镜像 init 导入 | 归一化管道 |
| `salt/elasticsearch/templates/component/*` | 导入 ES | ECS/DTC/so-* 映射模板 |
| `salt/zeek/policy/securityonion/*` | 打进 zeek 镜像 | JSON/CommunityID/sensorname/BPF/文件提取 |
| `salt/zeek/defaults.yaml` local.zeek 清单 | 渲染 local.zeek | 插件加载清单（按需裁剪） |
| `salt/zeek/files/{node,zeekctl,networks}.cfg.jinja` | 渲染模板 | Zeek 运行配置 |
| `salt/suricata/defaults.yaml` | 渲染 suricata.yaml | eve/pcap/af-packet 配置 |
| `salt/suricata/files/so_filters.rules`、`so_extraction.rules` | 内置规则集（默认禁用） | 日志裁剪/文件提取 |
| `salt/suricata/tools/*`（reload/restart/testrule） | 打进镜像 | 规则运维 |
| `so-import-pcap` 思路 | 后续可选 | 离线 pcap 分析 |

## 8. 开发里程碑

> 历史已下线里程碑（M5 Sigma 检测 / M7 Kibana 看板）见 `TODO.md` 历史段，不再作为现行范围。

### M0：镜像与容器化跑通（1-2 周）
- 交付：suricata / zeek 瘦身镜像、docker-compose 清单、配置模板、启动脚本。
- 验收：两引擎从镜像口抓包，eve.json 与 zeek JSON 日志正常落盘，无默认规则也能跑（0 告警）。

### M1：数据采集与归一化（1-2 周）
- 交付：filebeat / elasticsearch；ingest pipeline 导入（81 个：zeek.* + suricata.* + strelka.* + common）；数据流与 ILM。
- 验收：Zeek 元数据按 ECS 归一化入 ES（conn/dns/http/ssl/tls/smb/...），`event.dataset=zeek.conn` 正确，可被 XDR 通过 MCP 工具查询；不内置可视化组件。

### M2：告警与规则管理闭环（2-3 周）
- 交付：ndr-manager（含原 detections / xdr-push / cleaner / es-init 四服务并入）；suricata 规则热加载。
- 验收：自定义 / ET Open / 内置规则命中 → `logs-suricata.alerts-so` → xdr-push **实时 POST Webhook URL**（XDR 沙箱接收）；规则启停/阈值生效；重试、断点续传、幂等去重正常。

### M3：全包与运维完善（2 周）
- 交付：pcap-log 全包 + cleaner 阈值清理、文件提取 + Strelka、健康检查/审计日志、Helm Chart 化（k3s 时期产物，docker-compose 保留等效逻辑）。
- 验收：pcap 留存天数/存储上限可配置并自动清理；探针重启自愈；告警不丢失。

### M11：本地分析 Agent（LLM 噪声过滤，2026-08-15）
- 交付：ndr-agent（FastAPI + OpenAI 兼容 LLM）+ mcp-server（MCP streamable HTTP，6 个工具）。
- 验收：XDR 下发 `POST /api/xdr/agent/task` → Agent 通过 MCP 工具查本地 ES → LLM 给出"是否为真实威胁"的结论与证据链；未配置 LLM 时降级为结构化任务。

## 9. 扩展位（本期不做，设计预留）

- Redis/Kafka 队列：多探针/高吞吐时在采集器与 ES 之间插入（复用 SO 管道）。
- ~~Fleet/Elastic Agent~~：已启用（M9，见 §5.3），剩余为多探针管理面扩展。
- 多探针管理面：规则统一下发、探针状态汇总（本期 detections 为单探针形态）。
- Strelka 文件分析：文件提取后做 YARA/ClamAV（本期只提取不分析）。
- 离线 pcap 导入（so-import-pcap 思路）。

## 10. 待确认项（需要 XDR 侧/产品侧输入）

1. **Webhook 报文规范确认**：§5.8 草案（字段/幂等键/HMAC）是否与 XDR 侧约定一致，XDR 侧若有既有格式要求请提供。
2. **XDR 下发任务 schema**：`POST /api/xdr/task` 与 `POST /api/xdr/agent/task` 的请求/响应字段（target / datasets / window_seconds / conditions / instruction）是否与 XDR 编排系统对齐；如 XDR 侧有既定 schema 请提供。
3. **ES 版本与许可**：沿用 Elasticsearch 9.3.3（与 SO 资产 100% 兼容，但为 Elastic License 2.0）；如需 Apache 2.0 可换 OpenSearch（ingest pipeline 大体兼容，需小改）。建议默认 ES 9.3.3。
4. **LLM 模型对接**：默认指向 host.docker.internal:11434（Ollama，OpenAI 兼容）；需确认 XDR 下发"研判类"任务时携带的 instruction 格式与预期输出 schema。
5. **规则集初始来源**：默认空（已定）；ET Open 35 分类按需勾选启用；SO_FILTERS/SO_EXTRACTIONS 作为内置规则集（默认禁用，仅可启停）。

## 11. 技术风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| k8s 下 AF_PACKET 抓包权限/性能 | 抓包失败或丢包 | hostNetwork + privileged；容器内 setcap；按 SO 参数调优 ring-size/threads |
| 引擎与 ES 同机资源竞争 | 丢包/检索慢 | 资源 limits 预留；Zeek/Suricata worker 数按核数配置；ES heap 限制 |
| pcap 磁盘打爆 | 系统故障 | pcap-cleaner 双阈值（天数+容量）+ 启动自检 |
| 告警推送丢失/重复 | XDR 数据质量问题 | 游标持久化 + `document_id` 幂等 + 重试退避 + 死信 |
| Elastic License 合规 | 商业化受限 | §10.2 决策（OpenSearch 备选） |
| 引擎镜像体积大 | 部署慢 | 基于 SO 镜像瘦身（多阶段、裁剪依赖） |
