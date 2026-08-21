# NSS-NDR 项目 TODO

> **定位校准（2026-08-22）**：NDR 是**边缘自治 AI 探针**——自身采集流量 + 生产告警 + 本地分析；XDR 是云端裁决者，接收线索 + 最终处置。**M5（Sigma）/ M7（Kibana）已划归 XDR，不再属于本项目范围**。
>
> **弃置说明（2026-08-22）**：LLM Agent 子系统（M11 / M11b / M11c / M14 / M14.5）已拆除，迁移至独立项目维护。本项目聚焦数据管道（采集/存储/推送/取证），AI 分析能力不在本仓库范围内。

---

## 已完成里程碑

### M0 · 引擎容器化
- Suricata 8.0.5 / Zeek 8.0.8 镜像（基于 SO 3.1.0 瘦身）
- k3s 清单 + 配置模板 + Actions 构建

### M1 · 数据采集与归一化
- filebeat / elasticsearch（xpack security）镜像与清单
- 81 个自研 ingest pipeline（zeek.* + suricata.* + strelka.* + common）
- data stream（`logs-zeek-so` / `logs-suricata.alerts-so` / `logs-strelka-so`）+ ILM

### M2 · 规则管理与告警推送
- 规则 CRUD / 启停 / ET Open / 自定义（后续并入 M4 ndr-manager）
- xdr-push：ES 轮询 → Webhook 推送，游标 / 重试 / 去重 / HMAC（后续并入 M4）
- 阈值/抑制（规则内嵌 `threshold` 关键字，reload 即生效）
- 推送白名单默认收敛为 `suricata.alert`；修复 stats 污染

### M3 · 运维完善
- cleaner（全包 / 日志双阈值 + 磁盘压力兜底）
- ES 认证加固（xpack security + 应用用户 `filebeat` / `xdr-push`）
- 文件提取 + Strelka（M3b）
  - Zeek 提取策略（MIME 白名单 + 9MB 上限 + 完整性校验）
  - filecheck（watchdog + SHA1 history 去重）
  - Strelka 六组件 + frontend 57314
  - YARA：securityonion-yara（固定提交）+ 编译 `rules.compiled` 只读挂载
  - cleaner 增加 Strelka processed/log 留存清理

### M4 · 统一配置管理后台（ndr-manager）
- React SPA（Web UI：Dashboard / 参数配置 / 规则 / 历史审计）
- Go API + SQLite 配置库（configs / config_versions / audit / rules / users 5 张表）
- 配置渲染引擎（内置模板 + 扁平化 policy）
- detections / xdr-push / cleaner / es-init 四服务全部并入
- Webhook 推送 HMAC + 重试 + 死信 + 游标断点

### M6 · 数据总线管道（k3s 时期方案）
- Logstash 双 pipeline（beats/TLS 接收 → redis 缓冲 → search 消费 → ES）
- data_stream 路由 + metadata.pipeline 指派
- 自签 CA/证书（双向 TLS）
- 幂等机制：filebeat 稳定事件 ID → logstash create + document_id，重复 version_conflict 静默

### M8 / M9 · 采集层对齐 SO（k3s 时期）
- Elastic Agent（Fleet 托管）+ 三 filestream 输入
- Fleet Server + fleet-init Job 自动供给（策略 / 输出 / 集成 / 令牌）
- 部署验证：fleet-server/agent 双在线 + 数据链路实测（2026-08-11）
- 注：docker-compose 部署仍使用 standalone filebeat 直连 ES

### M10 · 引擎插件对齐 SO 3.1.0（2026-08-12）
- Zeek `local.zeek` 全量加载清单（标准脚本集 / ICS×8 / spicy×4 / tds / profinet / http2 / intel / cve-2020-0601）
- `config.zeek`（JA4 选项）+ cve-2020-0601 策略资产
- Suricata `so-suricata-testrule` / `so-suricata-rulestats` 运维脚本
- `GET /api/suricata/stats` 规则统计 API

### M12 · Web 运维监控可视化
- 后端 4 个端点（`monitoring.go`）：
  - `/api/monitoring/traffic`（zeek.conn date_histogram，最近 60 分钟 eps + bps 波形）
  - `/api/monitoring/workload`（当日事件总量 + 按 dataset 分布 + 告警线索 + Strelka 文件数 + XDR 推送计数）
  - `/api/monitoring/health`（组件 + ES + 磁盘 + cleaner）
  - `/api/monitoring/alerts-today`（今日线索按小时柱状图）
- XDR 推送 in-memory 计数器（成功 / 失败 / DLQ），在 `Push()` 内部埋点
- 前端 Dashboard 重写：4 张数字卡 + SVG 折线 + SVG 柱状图 + 组件健康表 + 磁盘进度条 + Cleaner + dataset Top10
- 纯 SVG 图表，不引第三方库；每 30s 自动刷新 + 手动刷新
- 边界声明：Dashboard 底部明确"安全数据分析可视化由 XDR 平台承担"

### M13 · 取证下载
- `GET /api/pcap/{name}`（pcap 下载，受用户会话鉴权 + 路径校验 + 2 GB 上限 + 流式）
- `GET /api/file/{md5}`（按 MD5 查找 Zeek 提取 / Strelka 已扫描样本）
- 两条下载端点均审计日志（`audit("file.download", ..., size=...)`）

### 部署验证（生产实例 10.44.77.250）
- docker-compose 全栈部署：suricata / zeek / es / filebeat / ndr-manager / strelka-* 全部 Running
- 镜像口参数化：`configs/probe.yaml`（interface=enp5s0）→ `deploy.sh render` → `/opt/ndr/so/conf/`
- 数据管道：eve.json + zeek JSON → filebeat → ES（logs-suricata.alerts-so / logs-zeek-so）
- 管理后台端口 30603 可访问
- 告警闭环：注入测试告警 → xdr-push → Webhook 重试 → 失败写死信
- suricata unix socket 热加载通道
- nss-ndr-manager 配置下发实测：保存 → 渲染 → 滚动重启 → 审计
- 部署机未改 k3s/rancher；`vm.max_map_count` 本机已 1048576

---

## 待验证 / 待办

### 部署验证缺口
- [ ] Strelka 端到端实测：zeek 提取 → filecheck → filestream → 扫描 → strelka.log → ES logs-strelka-so
- [ ] cleaner 阈值实测：观察 pcap 增长后按 retention/storage_limit 清理
- [ ] 接入真实 XDR Webhook 地址（替换测试地址）后重渲染配置

### 待确认项
- [ ] XDR 侧确认 Webhook 报文规范（告警字段 / 推送频率）
- [ ] ES 版本 / 许可：Elasticsearch 9.3.3（默认）还是 OpenSearch
- [ ] YARA 规则源扩展：构建期固定 securityonion-yara 提交，后续可加 UI 同步 / 自定义规则

---

## 已下线（划归 XDR / 独立项目，不在本项目维护）

### 划归 XDR（XDR 平台负责）
- **M5 Sigma 检测**（pySigma 转换、Sigma 规则管理、detections.alerts 索引、调度器）
- **M7 Kibana NDR 看板**（kibana-init sidecar、41 个看板导入、SO 模板改写）

### 迁移至独立项目（AI Agent 子系统）
- **M11 / M11b / M11c / M14 / M14.5**：ndr-agent（LangGraph StateGraph + qwen3-0.6B）+ mcp-server（12 个 MCP 分析工具）+ 内置 ollama 镜像 —— 已拆除，迁移至独立仓库
