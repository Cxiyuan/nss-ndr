# NSS-NDR 项目 TODO

## 里程碑进度

- [x] **M0 引擎容器化**：Suricata/Zeek 镜像、k3s 清单、配置模板、Actions 构建
- [x] **M1 本地检索闭环**：filebeat / elasticsearch(+es-init) / kibana 镜像与清单、自研 ingest pipelines
- [x] **M2 规则管理与告警推送**
  - [x] detections 服务（规则 CRUD / 启停 / 自定义规则 / suricata 热加载）
  - [x] xdr-push 服务（ES 轮询新告警 → Webhook 推送，游标/重试/去重/HMAC）
  - [x] 镜像构建与 k8s 清单
  - [ ] 阈值/抑制（threshold/suppress）规则支持（M3 补）
- [ ] **M3 运维完善**
  - [ ] cleaner（全包/日志双阈值 + 磁盘压力兜底）
  - [ ] 文件提取 + Strelka（可选）
  - [ ] Helm Chart 化
  - [ ] ES 认证加固（M1 暂关 security）

## 部署验证（待用户指定服务器）

- [ ] k3s 节点准备：`vm.max_map_count=262144`、`ghcr-pull` secret、/nsm 数据盘
- [ ] `kubectl apply -k deploy/k3s/` 验证全栈
- [ ] 验证 eve.json / zeek JSON 落盘与 ES 检索（M0/M1 验收）
- [ ] 验证自定义规则 → 告警 → Webhook 推送闭环（M2 验收）
- [ ] 验证 pcap 留存/清理阈值（M3 验收）

## 待确认项

- [ ] XDR 侧确认 Webhook 报文规范（docs/架构设计 §5.8）
- [ ] GHCR 包可见性：私有+secret（默认）还是公开
- [ ] ES 版本/许可：Elasticsearch 9.3.3（默认）还是 OpenSearch
- [ ] detections UI：先 REST API + 极简页，还是完整界面
- [ ] Zeek 轮转历史是否补采进 ES（默认只留档）
