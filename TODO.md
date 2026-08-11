# NSS-NDR 项目 TODO

## 里程碑进度

- [x] **M0 引擎容器化**：Suricata/Zeek 镜像、k3s 清单、配置模板、Actions 构建
- [x] **M1 本地检索闭环**：filebeat / elasticsearch(+es-init) / kibana 镜像与清单、自研 ingest pipelines
- [x] **M2 规则管理与告警推送**
  - [x] detections 服务（规则 CRUD / 启停 / 自定义规则 / suricata 热加载）
  - [x] xdr-push 服务（ES 轮询新告警 → Webhook 推送，游标/重试/去重/HMAC）
  - [x] 镜像构建与 k8s 清单
  - [x] 阈值/抑制（规则内嵌 threshold 关键字，reload 即生效）
- [x] **M3 运维完善**
  - [x] cleaner（全包/日志双阈值 + 磁盘压力兜底）
  - [x] Helm Chart 化
  - [x] ES 认证加固（xpack security + 应用用户）
  - [x] 文件提取 + Strelka（参照 SO 3.1.0）
    - [x] Zeek 提取策略（MIME 白名单 + 9MB 上限 + 完整性校验，M0 已随 zeek 镜像就绪）
    - [x] filecheck（watchdog + SHA1 history 去重 + 搬入 unprocessed；history 定时清理）
    - [x] Strelka 六组件 k3s/Helm 清单（coordinator/gatekeeper redis + frontend/backend/
          filestream/manager，frontend 57314）
    - [x] YARA 规则：securityonion-yara（固定提交）→ 宿主编译 rules.compiled 只读挂载（同 SO）
    - [x] 数据链路：strelka.log → filebeat（metadata.pipeline=strelka.file）→ logstash → ES
          （strelka.file pipeline + logs-strelka-so 数据流模板 + ILM）
    - [x] cleaner 增加 processed/log 留存清理；磁盘压力兜底纳入 strelka 已扫描目录
    - [x] manager 增加 strelka 配置段（enabled / backend_replicas / 留存）+ UI 页
    - [ ] 部署验证：构建镜像并 pin newTag 后，k3s/Helm 实测端到端
- [x] **M7 Kibana NDR 看板（复用 SO 模板）**
  - [x] 从参考机 SO 3.1.0 导出 41 个核心看板（+154 关联对象，共 195 个）
  - [x] 批量改名 `Security Onion - *` → `NDR - *`（322 处），修复 .keyword 字段（24 处）
  - [x] 资产入库：images/kibana-init/files/dashboards.ndjson
  - [x] kibana-init sidecar 自动导入（Kibana 就绪后 _import overwrite，失败重试）
  - [x] 2026-08-11 重装后手工导入恢复（41 看板/195 对象 0 失败）
  - [ ] kibana-init 镜像构建后随 CI 自动生效（当前部署机已手工导入，等价）
- [x] **M8 采集层对齐 SO：filebeat → Elastic Agent（standalone）**
  - [x] 新增 elastic-agent 镜像（standalone agent.yml，policy 格式同 SO）
  - [x] 三 filestream 输入：suricata-eve / zeek-logs / strelka-logs（含 exclude、dissect、
        JS 管道路由与幂等事件 ID）
  - [x] 输出 Lumberjack + 双向 TLS 到 Logstash 5055（对齐 SO Fleet logstash output）
  - [x] k3s/Helm 清单、render/manager/CI 全部替换 filebeat
  - [ ] 部署验证：构建镜像后实测数据链路（待 CI）
- [x] **M4 统一配置管理后台（nss-ndr-manager）**
  - [x] React SPA（Web UI：总览/探针/Suricata/Zeek/ES/告警推送/规则/历史审计）
  - [x] Go API + SQLite 配置库（版本历史 + 审计日志）
  - [x] 配置渲染引擎（内置模板 + 扁平化 policy）+ k8s API 下发（ConfigMap + 滚动重启）
  - [x] 规则管理并入（CRUD/启停/内置规则/热加载），detections 服务移除
- [x] 部署到 10.44.77.250 并验证下发链路（NodePort 30603）
- [x] 2026-08-10 全新部署（删除旧命名空间/数据后重装最新版）：9 组件 Running、数据总线/幂等/Sigma(pySigma) 全部验证通过
- [x] **M5 Sigma 检测**
  - [x] `logs-detections.alerts-so` 数据流/模板/pipeline（es-init）
  - [x] manager Sigma 规则管理（SQLite CRUD/启停/导入/转换预览，UI 页）
  - [x] Sigma→ES 查询转换器（网络类字段映射 + selection/condition 解析）
  - [x] 检测调度器（按 schedule 定时执行，命中写告警，payload 对齐 SO）
  - [x] 内置 5 条网络类 Sigma 规则（默认禁用）
  - [x] xdr-push 扩展推送 detections.alerts（Webhook/死信）
  - [x] 修复数据链路：zeek 各日志类型 pipeline、event.dataset keyword 映射、dns/http/tls 字段映射
  - [x] 端到端验证：启用规则→执行→告警写入 detections 索引→Webhook 推送（18888 测试地址写死信）
  - [x] 转换器升级为 pySigma 标准做法（对齐 SO）：sigma CLI + 自定义字段映射管道，废弃自研转换器
  - [x] 内置规则 id 改为标准 UUID，兼容通用 Sigma 规范（SigmaHQ）规则文件
- [x] **M6 数据总线管道（参照 SO 3.1.0）**
  - [x] Logstash 双 pipeline（manager 5055 beats/TLS 接收 → redis 缓冲 → search 消费 → ES）
  - [x] Redis 缓冲（list + 背压 + 批量）
  - [x] filebeat 改 Lumberjack 输出（双向 TLS，client 证书）
  - [x] data_stream 路由 + metadata.pipeline 指派 ES ingest pipeline
  - [x] 自签 CA/证书（scripts/gen-certs.sh → Secret nss-ndr-certs）
  - [x] zeek 全日志类型 pipeline 补齐（62 类）
  - [x] 端到端验证：filebeat→logstash→redis→logstash→ES 全链路零错误
  - [x] 幂等机制（对齐 SO）：filebeat 生成稳定事件 ID（metadata._id），logstash create + document_id，重复事件 version_conflict 静默
  - [x] 修复 suricata pipeline 根字段提取（filebeat ndjson 无 message），event.dataset 正确

## 部署验证（2026-08-09 已完成，10.44.77.250）

- [x] `kubectl apply -k deploy/k3s/` 全栈部署：suricata/zeek/es/filebeat/kibana/detections/xdr-push/cleaner 全部 Running
- [x] 镜像口参数化：`configs/probe.local.yaml`（interface=enp5s0，不入库）→ `render-configs.py` 生成 ConfigMap
- [x] 数据管道：eve.json + zeek JSON 落盘 → filebeat → ES（`logs-suricata.alerts-so` / `logs-zeek-so`，自定义 pipeline/ILM/模板）
- [x] Kibana 30601 / detections 30602 NodePort 可访问
- [x] 告警闭环：注入测试告警 → xdr-push 查询命中 → Webhook 重试推送 → 失败写死信（18888 为测试地址）
- [x] suricata unix socket 热加载通道（detections reload-rules）
- [x] nss-ndr-manager 配置下发实测：保存 probe/xdr 配置 → ConfigMap 更新（interface=enp5s0）→ 7 组件滚动重启 → 审计记录
- [ ] Strelka 端到端实测（待镜像构建）：zeek 提取 → filecheck → filestream → 扫描 →
      strelka.log → ES logs-strelka-so → Kibana SOC Files 视图
- [x] 部署机未改 k3s/rancher 配置；`vm.max_map_count` 本机已 1048576（满足 ES 要求），未做系统级修改
- [ ] 清理阈值实测：cleaner 已跑（Completed），需观察 pcap 增长后按 retention/storage_limit 清理（M3 验收）
- [ ] 接入真实 XDR Webhook 地址（替换 `probe.local.yaml` 中 18888 测试 URL 后重新渲染 ConfigMap）

## 待确认项

- [x] GHCR 包可见性：仓库级命名空间 `ghcr.io/cxiyuan/nss-ndr/*`，随 public 仓库自动公开（方法B）
- [ ] XDR 侧确认 Webhook 报文规范（docs/架构设计 §5.8）
- [ ] ES 版本/许可：Elasticsearch 9.3.3（默认）还是 OpenSearch
- [ ] Zeek 轮转历史是否补采进 ES（默认只留档）
- [ ] manager 配置初始化：部署后需在 UI 填写镜像口/Webhook 再首次下发（当前已用 API 写入）
- [ ] Sigma 规则源扩展：支持从 SigmaHQ 仓库拉取/同步（当前内置 + 手动导入）
- [ ] YARA 规则源扩展：构建期固定 securityonion-yara 提交，后续可加 UI 同步/自定义规则
