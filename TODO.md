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
  - [ ] 文件提取 + Strelka（可选，延后）
- [x] **M4 统一配置管理后台（nss-ndr-manager）**
  - [x] React SPA（Web UI：总览/探针/Suricata/Zeek/ES/告警推送/规则/历史审计）
  - [x] Go API + SQLite 配置库（版本历史 + 审计日志）
  - [x] 配置渲染引擎（内置模板 + 扁平化 policy）+ k8s API 下发（ConfigMap + 滚动重启）
  - [x] 规则管理并入（CRUD/启停/内置规则/热加载），detections 服务移除
  - [x] 部署到 10.44.77.250 并验证下发链路（NodePort 30603）

## 部署验证（2026-08-09 已完成，10.44.77.250）

- [x] `kubectl apply -k deploy/k3s/` 全栈部署：suricata/zeek/es/filebeat/kibana/detections/xdr-push/cleaner 全部 Running
- [x] 镜像口参数化：`configs/probe.local.yaml`（interface=enp5s0，不入库）→ `render-configs.py` 生成 ConfigMap
- [x] 数据管道：eve.json + zeek JSON 落盘 → filebeat → ES（`logs-suricata.alerts-so` / `logs-zeek-so`，自定义 pipeline/ILM/模板）
- [x] Kibana 30601 / detections 30602 NodePort 可访问
- [x] 告警闭环：注入测试告警 → xdr-push 查询命中 → Webhook 重试推送 → 失败写死信（18888 为测试地址）
- [x] suricata unix socket 热加载通道（detections reload-rules）
- [x] nss-ndr-manager 配置下发实测：保存 probe/xdr 配置 → ConfigMap 更新（interface=enp5s0）→ 7 组件滚动重启 → 审计记录
- [x] 部署机未改 k3s/rancher 配置；`vm.max_map_count` 本机已 1048576（满足 ES 要求），未做系统级修改
- [ ] 清理阈值实测：cleaner 已跑（Completed），需观察 pcap 增长后按 retention/storage_limit 清理（M3 验收）
- [ ] 接入真实 XDR Webhook 地址（替换 `probe.local.yaml` 中 18888 测试 URL 后重新渲染 ConfigMap）

## 待确认项

- [x] GHCR 包可见性：仓库级命名空间 `ghcr.io/cxiyuan/nss-ndr/*`，随 public 仓库自动公开（方法B）
- [ ] XDR 侧确认 Webhook 报文规范（docs/架构设计 §5.8）
- [ ] ES 版本/许可：Elasticsearch 9.3.3（默认）还是 OpenSearch
- [ ] Zeek 轮转历史是否补采进 ES（默认只留档）
- [ ] manager 配置初始化：部署后需在 UI 填写镜像口/Webhook 再首次下发（当前已用 API 写入）
