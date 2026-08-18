# NSS-NDR 项目 TODO

## 边界声明（2026-08-15 重新校准）

NDR 是网络流量数据生产侧的探针单元。**承担范围**：

- 抓包（尽可能完整的 pcap）→ 元数据解构 → 告警线索生产 → 线索推送 XDR
- 执行 XDR 下发的分析任务（含 LLM 噪声过滤）
- 本地 Web 后台：**仅提供本探针自身的运维监控可视化**（流量波形图 / 当日工作量统计 / 组件健康 / 配置规则审计），不提供安全数据分析可视化

**不在 NDR 范围内（划归 XDR）**：

- 安全数据可视化（具体告警下钻 / 跨会话关联 / SOC 视图 / Hunt）
- Sigma 规则库与关联规则编排
- 跨探针关联、工单、研判决策

> 一句话总结：**NDR Web = 本探针运维监控（"这台机器在干什么、干了多少"）；XDR Web = 安全数据研判（"这些事件意味着什么、要不要处置"）**。

下列历史里程碑已下线，相关代码与文档不再维护：

- **M5 Sigma 检测**（pySigma 转换、Sigma 规则管理、detections.alerts 索引、调度器）—— XDR 负责
- **M7 Kibana NDR 看板**（kibana-init sidecar、41 个看板导入、SO 模板改写）—— XDR 负责

NDR 仍保留 Suricata 规则管理（内置 + ET Open + 自定义）作为**线索生产**手段；最终裁决（是否为真实威胁）由 XDR 通过下发分析任务 + NDR 端 LLM 噪声过滤完成。

## 里程碑进度

- [x] **M0 引擎容器化**：Suricata/Zeek 镜像、k3s 清单、配置模板、Actions 构建
- [x] **M1 数据采集与归一化**：filebeat / elasticsearch(+es-init) 镜像与清单、自研 ingest pipelines
- [x] **M2 规则管理与告警推送**
  - [x] detections 服务（规则 CRUD / 启停 / 自定义规则 / suricata 热加载）—— 后续并入 M4 ndr-manager
  - [x] xdr-push 服务（ES 轮询新告警 → Webhook 推送，游标/重试/去重/HMAC）—— 后续并入 M4
  - [x] 镜像构建与 k8s 清单
  - [x] 阈值/抑制（规则内嵌 threshold 关键字，reload 即生效）
  - [x] ~~三层信号模型（Suricata=线索 / Zeek=上下文 / Sigma=最终告警）~~ —— Sigma 部分划归 XDR，
        NDR 保留"线索标记"语义（`nss.detection.stage=clue` + tags `alert,clue`）
  - [x] xdr-push 推送白名单默认收敛为 `suricata.alert`（Sigma 关联确认已下线）
  - [x] 修复 stats 污染：eve-log stats 输出默认关闭 + agent 侧丢弃非 alert 事件
- [x] **M3 运维完善**
  - [x] cleaner（全包/日志双阈值 + 磁盘压力兜底）
  - [x] Helm Chart 化（k3s 时期）
  - [x] ES 认证加固（xpack security + 应用用户）
  - [x] 文件提取 + Strelka（参照 SO 3.1.0）
    - [x] Zeek 提取策略（MIME 白名单 + 9MB 上限 + 完整性校验）
    - [x] filecheck（watchdog + SHA1 history 去重 + 搬入 unprocessed；history 定时清理）
    - [x] Strelka 六组件 k3s/Helm 清单（coordinator/gatekeeper redis + frontend/backend/
          filestream/manager，frontend 57314）
    - [x] YARA 规则：securityonion-yara（固定提交）→ 宿主编译 rules.compiled 只读挂载（同 SO）
    - [x] 数据链路：strelka.log → filebeat（metadata.pipeline=strelka.file）→ logstash → ES
          （strelka.file pipeline + logs-strelka-so 数据流模板 + ILM）
    - [x] cleaner 增加 processed/log 留存清理；磁盘压力兜底纳入 strelka 已扫描目录
    - [x] manager 增加 strelka 配置段（enabled / backend_replicas / 留存）+ UI 页
    - [ ] 部署验证：构建镜像并 pin newTag 后，docker-compose 实测端到端
- [x] **M8 采集层对齐 SO：filebeat → Elastic Agent（k3s 时期，docker-compose 未启用）**
  - [x] 新增 elastic-agent 镜像（官方 docker.elastic.co/elastic-agent/elastic-agent，Fleet 托管）
  - [x] 三 filestream 输入：suricata-eve / zeek-logs / strelka-logs（含 exclude、dissect、
        JS 管道路由与幂等事件 ID）
  - [x] 输出 Logstash 5055（mTLS，Fleet logstash output 语义，对齐 SO）
  - [x] k3s/Helm 清单、render/manager/CI 全部替换 filebeat
  - [x] 部署验证：数据链路实测（zeek/suricata 经 elastic-agent → Logstash → ES 入库，2026-08-11）
  - 注：当前 docker-compose 部署仍使用 standalone filebeat 直连 ES（链路更短）；
    若启用 elastic-agent 链路需部署 Logstash + Redis（k3s 时期的 M6 组件）
- [x] **M9 补齐 Fleet（对齐 SO 3.1.0）**
  - [x] Fleet Server Deployment（elastic-agent fleet-server 模式，8220，服务端证书）
  - [x] fleet-init Job：ES service token / Fleet host / logstash 输出（双向 TLS）/
        策略（FleetServer-nss + nss-ndr）/ filestream×3 集成 / enrollment token →
        写 Secret nss-fleet-enrollment
  - [x] elastic-agent 改 Fleet 接入（FLEET_ENROLL=1 + FLEET_URL + token + FLEET_CA 路径）
  - [x] gen-certs 增加 fleet-server 服务端证书（SAN nss-fleet-server）
  - [x] 部署验证：fleet-server/agent 双在线 + 策略下发 + 数据链路实测（2026-08-11，45e7f3e）
  - [x] 产品化修复（2026-08-11）：fleet-init 输出顺序对齐 SO、Secret 写集合路径、移除 data 卷挂载
- [x] **M10 suricata/zeek 插件与脚本对齐 SO 3.1.0（2026-08-12）**
  - [x] zeek local.zeek 全量加载清单（标准脚本集/ICS×8/spicy×4/tds/profinet/http2/intel/
        cve-2020-0601/detect-windows-shells）
  - [x] config.zeek（JA4 选项，覆盖 ja4 包内配置）与 cve-2020-0601 策略资产入库并下发
  - [x] suricata 补 so-suricata-testrule / so-suricata-rulestats（容器内脚本）
  - [x] ndr-manager 新增 GET /api/suricata/stats（规则统计等价 API）
  - [ ] 部署验证：全量插件加载无报错 + testrule/rulestats 实测（待 CI）
- [x] **M4 统一配置管理后台（nss-ndr-manager）**
  - [x] React SPA（Web UI：总览/参数配置/事件检测/自定义规则/历史审计）
  - [x] Go API + SQLite 配置库（版本历史 + 审计日志）
  - [x] 配置渲染引擎（内置模板 + 扁平化 policy）+ docker-compose 配置下发
  - [x] 规则管理并入（CRUD/启停/ET Open/热加载），原 detections 服务下线
  - [x] xdr-push 并入（Webhook 推送 + HMAC + 重试 + 死信 + 游标断点）
  - [x] ES 初始化并入（pipeline/ILM/索引模板导入 + 应用用户）
  - [x] cleaner 并入（按 probe.yaml 阈值周期清理 + 磁盘压力兜底）
- [x] 部署到 10.44.77.250 并验证下发链路（管理后台端口 30603）
- [x] 2026-08-10 全新部署（删除旧命名空间/数据后重装最新版）：组件 Running、数据总线/幂等 全部验证通过
- [x] **M6 数据总线管道（参照 SO 3.1.0）**
  - [x] Logstash 双 pipeline（manager 5055 beats/TLS 接收 → redis 缓冲 → search 消费 → ES）
  - [x] Redis 缓冲（list + 背压 + 批量）
  - [x] filebeat 改 Lumberjack 输出（双向 TLS，client 证书）
  - [x] data_stream 路由 + metadata.pipeline 指派 ES ingest pipeline
  - [x] 自签 CA/证书（releases/gen-certs.sh → Secret nss-ndr-certs）
  - [x] zeek 全日志类型 pipeline 补齐（73 类）
  - [x] 端到端验证：filebeat→logstash→redis→logstash→ES 全链路零错误
  - [x] 幂等机制（对齐 SO）：filebeat 生成稳定事件 ID（metadata._id），logstash create + document_id，重复事件 version_conflict 静默
  - [x] 修复 suricata pipeline 根字段提取（filebeat ndjson 无 message），event.dataset 正确
- [x] **M11 本地分析 Agent（LLM 噪声过滤）**
  - [x] ndr-agent（Python FastAPI）：OpenAI 兼容协议（Ollama），MCP streamable HTTP 客户端，工具调用循环
  - [x] mcp-server（Python）：暴露 6 个工具——query_metadata / correlate_session /
        aggregate_stats / get_clue / query_files / list_datasets，全部直连本地 ES，数据不出设备
  - [x] ndr-manager 新增 `POST /api/xdr/agent/task`（Bearer 令牌认证）→ 转发到 ndr-agent
  - [x] 结构化降级：未配置 LLM 时直接调工具汇总
  - [x] docker-compose 集成（ndr-manager / mcp-server / ndr-agent 三件套）
  - [x] 配置项：`xdr.agent_enabled`（启用开关）+ `xdr.agent_url`（Agent 地址，默认 `http://nss-ndr-agent:8081/analyze`）
- [x] **M12 本地 Web 运维监控可视化**
  - [x] 后端 4 个端点（`monitoring.go`）：`/api/monitoring/traffic`（流量波形）、
        `/api/monitoring/workload`（当日工作量）、`/api/monitoring/health`（组件/ES/磁盘/cleaner）、
        `/api/monitoring/alerts-today`（今日线索分时柱状图）
  - [x] XDR 推送 in-memory 计数器（成功/失败/DLQ），在 Push() 内部埋点
  - [x] 前端 Dashboard.tsx 重写：顶部 4 张数字卡 + 流量波形图（纯 SVG 折线）+ 告警线索分时柱状图 +
        组件健康表 + 磁盘用量进度条 + Cleaner 状态 + dataset Top10 分布
  - [x] 纯 SVG 图表，不引第三方库；每 30s 自动刷新 + 手动刷新按钮
  - [x] 边界声明：Dashboard 页底部明确"具体告警事件内容、跨会话关联、SOC 视图等安全数据分析可视化由 XDR 平台承担"

## 部署验证（2026-08-09 已完成，10.44.77.250）

- [x] docker-compose 全栈部署：suricata/zeek/es/filebeat/ndr-manager/mcp-server/ndr-agent/strelka-* 全部 Running
- [x] 镜像口参数化：`configs/probe.yaml`（interface=enp5s0）→ `deploy.sh render` → `/opt/ndr/so/conf/`
- [x] 数据管道：eve.json + zeek JSON 落盘 → filebeat → ES（`logs-suricata.alerts-so` / `logs-zeek-so`，自定义 pipeline/ILM/模板）
- [x] 管理后台 NodePort 30603 可访问（设备管理 + 规则 + 历史审计）
- [x] 告警闭环：注入测试告警 → xdr-push 查询命中 → Webhook 重试推送 → 失败写死信（18888 为测试地址）
- [x] suricata unix socket 热加载通道（ndr-manager reload-rules）
- [x] nss-ndr-manager 配置下发实测：保存 probe/xdr 配置 → 渲染配置 + 滚动重启组件 → 审计记录
- [ ] Strelka 端到端实测（待镜像构建）：zeek 提取 → filecheck → filestream → 扫描 →
      strelka.log → ES logs-strelka-so（数据链路验证即可，可视化在 XDR）
- [x] 部署机未改 k3s/rancher 配置；`vm.max_map_count` 本机已 1048576（满足 ES 要求），未做系统级修改
- [ ] 清理阈值实测：cleaner 已跑（Completed），需观察 pcap 增长后按 retention/storage_limit 清理（M3 验收）
- [ ] 接入真实 XDR Webhook 地址（替换 `probe.local.yaml` 中 18888 测试 URL 后重新渲染配置）
- [ ] LLM 噪声过滤端到端：XDR 真实任务下发 → ndr-agent 调用 mcp-server 工具 → LLM 给出结论

## 待确认项

- [x] GHCR 包可见性：仓库级命名空间 `ghcr.io/cxiyuan/nss-ndr/*`，随 public 仓库自动公开（方法B）
- [ ] XDR 侧确认 Webhook 报文规范（docs/架构设计 §5.8）
- [ ] ES 版本/许可：Elasticsearch 9.3.3（默认）还是 OpenSearch
- [ ] Zeek 轮转历史是否补采进 ES（默认只留档）
- [ ] manager 配置初始化：部署后需在 UI 填写镜像口/Webhook 再首次下发（当前已用 API 写入）
- [ ] LLM 模型对接：默认指向 host.docker.internal:11434（Ollama），需确认 XDR 下发任务时携带的 schema
- [ ] YARA 规则源扩展：构建期固定 securityonion-yara 提交，后续可加 UI 同步/自定义规则
