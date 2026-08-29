# 智能体代码开发 TODO

> 依据：`设计文档/安全分析智能体设计v05.docx`（下称"设计文档"）
> 代码位置：`src/agent/`
> 范围：**只做智能体本身的代码开发**。
> - 大模型运行环境不在范围内：智能体只对接外部提供的 OpenAI 兼容模型接口（本地边缘 + 云端高阶，差异仅配置）
> - 容器镜像、Salt 部署、上线运维不在当前范围内（后续另行规划）
> - 数据总线已在服务器生产运行：智能体消费其 Redis Stream `analysis:events`（Logstash 双写产出，见
>   `src/databus/logstash/pipeline/zeek-pipeline.conf`），复用 ES（回溯/落盘）与 Redis（Stream/缓存/水位）

---

## 里程碑总览

| 里程碑 | 内容 | 主要交付物 |
|---|---|---|
| M0 | 契约冻结 | Schema、缓存键规范、配置模型、与数据总线对接契约 | ✅ |
| M1 | 代码库搭建 | `src/agent/` 骨架、配置加载、Schema 落地 | ✅ |
| M2 | 核心组件 | 存储层、规则引擎、Provider 网关、MCP、LangGraph 管线、Worker | ✅ |
| M3 | 辅助能力 | Skills 加载、告警闭环、资产知识库、可观测性、基线/异常检测引擎 | ✅ |
| M4 | 测试与本地验证 | 单测、fake 依赖、采样回放、端到端（测试事件） | ✅ 单测 31 个通过；生产 dry-run 待做 |

---

## M0 契约冻结（先定契约，再写代码）

- [x] **C1 模型接口契约**（设计文档 §15）：双 Provider 均为 OpenAI 兼容 API，配置项 `base_url / api_key / model / max_context / capabilities`（tool_calling、json_schema、streaming）；Provider 抽象接口 `generate / stream / estimate_tokens / get_metadata`（`app/providers/`）
- [x] **C2 Schema 契约**（设计文档 §13）：pydantic/dataclass + JSON Schema 落码（`app/schemas/`）
  - 事件信封：event_id、@timestamp、五元组、proto、富化标签、trace_id
  - analysis_unit：会话键、聚合窗口、三层聚合摘要、命中 BEH 与初始风险、预估工具调用次数、升级标志、watermark
  - verdict：risk_level、verdict、evidence、iocs、suggest_action、model、ver、watermark、trace_id、created_at
- [x] **C3 缓存键规范**（设计文档 §13.4、§4.3）：`sess:{src}:{dst}:{dst_port}:{proto}`、`evt:{event_id}`（TTL 24h）、`lock:{会话键}`、`alert:{指纹}`、`agent:result:{会话键}`（TTL 1h）、`agent:entity:{IP}`（TTL 24h）、`agent:chain:{ID}`（TTL 48h）；IPv6 规范化或哈希（`app/schemas/keys.py`）
- [x] **C4 数据总线对接契约**：Redis Stream `analysis:events`、消费组 `analysis-group`；ES 地址/口令、Redis 地址/口令从环境变量/`.env` 读取（复用 `/etc/nss-ndr/.env` 键名）（`app/config.py`）
- [x] **C5 v1 范围**：规则引擎（BEH-001~012）+ 双 Provider 网关 + MCP 4 个关联工具 + 缓存/水位 + 告警落 ES；基线引擎、向量 RAG、Skills 动态路由按序后置

---

## M1 代码库搭建

目标目录结构：

```text
src/agent/
├── TODO.md                        # 本文件
├── README.md                      # 运行说明、配置项、与数据总线关系
├── pyproject.toml / requirements.txt
├── app/
│   ├── __init__.py
│   ├── config.py                  # 配置加载（agent.yaml + providers.yaml + 环境变量/.env）
│   ├── schemas/                   # 事件信封 / analysis_unit / verdict / 缓存键（M0-C2/C3）
│   ├── storage/                   # redis.py / es.py / lua 脚本
│   ├── rules/                     # BEH 规则引擎 + 三层聚合 + shadow 模式
│   ├── providers/                 # LLM Provider 抽象 + 模型网关（needs_cloud/配额/熔断/降级）
│   ├── mcp/                       # MCP Client（两级发现/Schema 缓存/参数校验）+ MCP Servers
│   ├── pipeline/                  # LangGraph 图定义 + 节点实现 + Checkpoint
│   ├── worker.py                  # 常驻 Worker：消费组/批处理/XAUTOCLAIM/背压
│   ├── skills/                    # SKILL.md 加载与路由（三层渐进式）
│   ├── assets/                    # 资产知识库（档案模型/导入/RAG 检索）
│   ├── alerting/                  # 事件模型/状态机/去重/通知
│   └── observability/             # trace_id、指标、结构化日志
├── config/
│   ├── agent.yaml                 # 批窗口/水位/TTL/路径
│   ├── providers.yaml             # edge/cloud Provider 注册表
│   └── rules/*.yaml               # BEH-001~012 声明式规则
├── prompts/                       # 系统层/资产上下文层/任务层/输出约束层
├── skills/*.md                    # 场景化 Skills（模板见设计文档 §7.3）
├── data/                          # 资产档案种子（CSV/JSON）
├── tests/
├── Dockerfile                     # 仅备后续打包用，不在当前范围
└── entrypoint.sh                  # 仅备后续部署用，不在当前范围
```

- [x] 1.1 目录骨架 + 依赖清单（langgraph、openai 兼容 client、redis-py、elasticsearch-py、mcp SDK、pydantic、structlog、prometheus-client、pytest）
- [x] 1.2 配置加载：`agent.yaml` / `providers.yaml` / 环境变量；环境无关（设计文档 §15.1）
- [x] 1.3 Schema 契约落地 + 单测锁死字段
- [x] 1.4 测试骨架：内存 Redis/ES fake + fake LLM 接口，目标机外可开发

---

## M2 核心组件

- [x] 2.1 存储层
  - Redis：Streams 消费组（`analysis:events` / `analysis-group`）、批拉取、XAUTOCLAIM 重投、sess/evt/lock/alert/agent:* 键管理、水位 + 结论原子写回 Lua（设计文档 §3、§13.5）
  - ES：事件回溯查询、verdict 历史落盘（`nss-ndr-agent-verdict-*`）、资产档案检索（v1 用 keyword/BM25）、ILM 创建（初始化脚本内）
- [x] 2.2 规则引擎（设计文档 §5.5）：BEH-001~012 声明式规则 + 会话/流/主机三层聚合 + 直接判定（BEH-005 不送模型）+ 升级标志（requires_chain_analysis / behavior_hits / estimated_tool_calls）+ shadow 模式
- [x] 2.3 LLM Provider 抽象与模型网关（设计文档 §8、§15）：OpenAI 兼容 `generate/stream/estimate_tokens/get_metadata`；`needs_cloud` 硬编码判定；配额/并发/熔断/降级（uncertain 入队）
- [x] 2.4 MCP（设计文档 §6）：Client 两级发现（启动 tools/list 缓存 Schema、上下文只注入工具目录、调用时补全校验、结果截断 ≤512 tokens）；Servers：`es_search`、`query_peer_relations`、`count_behavior_hits`、`detect_chain_sequence`、`get_entity_profile`
- [x] 2.5 LangGraph 管线（设计文档 §9）：`cache_lookup → aggregate → model(edge) → escalate_check → model(cloud)/tool_loop → verdict_write → alert`；条件边；Checkpoint（v1 InMemory，Redis Checkpoint 待接）
- [x] 2.6 Worker 主循环：批窗口（1000 条或 5 秒）、背压降级、单飞锁、幂等（evt SETNX TTL 24h）、崩溃恢复（XAUTOCLAIM）

---

## M3 辅助能力

- [x] 3.1 Skills 加载器（设计文档 §7）：Discovery 索引常驻 / Activation 按需加载 / Execution 资源动态加载；triggers 与 BEH 编号对应（样例：DNS 隧道 / SSH 爆破）
- [x] 3.2 告警与事件闭环（设计文档 §11）：事件模型 + 状态机（open→triage→confirmed/in_progress→closed / false_positive）+ 告警指纹去重 + 通知抽象（v1 ES 落库 + 日志，Webhook 可配置）
- [x] 3.3 资产知识库（设计文档 §10）：档案模型、CSV/CMDB 导入、被动测绘占位、档案变更联动缓存失效（`invalidate_prefix` 已备）
- [x] 3.4 可观测性（设计文档 §12）：trace_id 贯穿、节点级 span、指标分层（管道/分析/业务/成本）、结构化日志
- [x] 3.5 基线/异常检测引擎（设计文档 §14）：三阶段冷启动、t-digest/EWMA、抗污染、阈值自适应

### M3.6 基线引擎实现明细（2026-08-29 纳入计划）

- [x] t-digest 在线分位数草图（`app/baseline/sketches.py`）：增量更新 / P5-P99 查询 / 跨 worker merge / Redis 序列化
- [x] 指标维度（v1 子集）：连接数、唯一目标 IP、唯一端口、失败率、DNS 频次/唯一域名、HTTP 频次/唯一 URI（主机粒度）
- [x] 三阶段冷启动：shadow（只记录不告警）→ loose（阈值 ×2、低置信度）→ converged（设计文档 §14.1）
- [x] 抗污染：P99 + 3×MAD 越界观测降权学习、High 事件跳过学习（设计文档 §14.4）
- [x] 阈值自适应：每实体每日告警预算 Top-N、误报反馈放宽阈值（设计文档 §14.5、§14.6）
- [x] 与管线集成：anomaly_unit 并入 LangGraph aggregate 节点；异常高分升级云端复核（`needs_cloud` 新增 `anomaly_alert`）
- [ ] 后续演进（P2）：5m/1h/24h 多窗口精细滚动聚合、host-port/host-peer 粒度、t-digest 草图落 Redis（多 worker 合并）、节假日/维护窗口日历

### M3.7 容器镜像（2026-08-29 完成）

- [x] `images/Dockerfile.agent`：python:3.12-slim + `pip install .` 依赖锁定 + 内置 `app/config/prompts/skills/data`；非 root（uid 10001）+ HEALTHCHECK；`ENTRYPOINT ["python","-m","app"]`，默认 `worker`
- [x] `images/scripts/build-agent.sh`：`docker build --platform linux/amd64` + `docker save`（沿用数据总线 build 脚本模式）
- [x] 产物：`images/offline/nss-ndr_agent_0.1.0.tar`（67M，镜像 312M）；容器内 `version/once` 冒烟通过（无 Redis 优雅降级）

---

## M4 测试与本地验证

- [x] 4.1 单元测试：规则引擎（BEH 用例）、Schema 校验、缓存/水位 Lua、needs_cloud 分支、MCP 参数校验（31 个通过）
- [x] 4.2 采样回放：构造 BEH-001~012 采样事件 → 全链路（聚合→模型→工具→verdict）本地跑通（pytest 覆盖缓存命中/升级云端/规则直接判定）
- [x] 4.3 对接生产数据总线（只读验证）：`analysis:events` 真实流量消费 + 解析/聚合/出结论正确（M4 部署后容器内验证）
- [ ] 4.4 可观测性验收：指标/日志/trace 输出可查

## M5 Salt 部署（2026-08-29 完成，`src/agent/salt/`，对齐数据总线）

目标服务器 `172.16.199.235`（masterless salt-minion 3006.9，与数据总线同机）。

- [x] `pillar.example` → `/srv/pillar/agent.sls`：镜像 `nss-ndr/agent:0.1.1`、固定 IP `.80`、配置路径
- [x] `map.jinja`：复用数据总线 `.env` 的 `env_get` 宏（ES/REDIS/LLM 密钥不入 pillar）
- [x] `images.sls`：从 `/root/nss-agent/nss-ndr_agent_0.1.1.tar` load（不拉取不构建）
- [x] `configs.sls`：`agent.yaml / providers.yaml / rules/beh-rules.yaml` → `/etc/nss-ndr/agent/`，容器只读挂载
- [x] `bootstrap.sls`：预检 databus ES/Redis 运行中（不满足则阻断）
- [x] `setup.sls` + `agent-setup.sh`：ES 索引 + ILM、Redis 消费组 `analysis-group`、`.env` 补 `AGENT_DRY_RUN=1` 与 LLM 空默认值
- [x] `containers/agent.sls`：`nss-ndr-agent` 容器，固定 IP `192.168.250.80` + alias `agent`，healthcheck，restart_policy unless-stopped
- [x] `deploy.sls` 编排：images → configs → 预检 → setup → 容器 → verify（`salt-call --local state.apply agent.deploy` 全绿）
- [x] `verify.sls`：容器状态 + `analysis-group` 存在 + worker 日志
- [x] `teardown.sls` / `saltctl.sh`：清理与日常操作（已就绪未执行清理）
- [x] 部署结果：容器 healthy，消费生产 `analysis:events` 真实流量，日志正常产出 verdict；**当前 dry-run + LLM 未配置 → uncertain 属预期**
- [ ] 上线写回：`.env` 填 `EDGE_LLM_*`/`CLOUD_LLM_*` + `AGENT_DRY_RUN=0`，再 `salt-call --local state.apply agent.containers.agent` 重建容器

## 当前进度（2026-08-29）

开发语言 **Python 3.12**（LangGraph + pydantic + redis-py + elasticsearch-py + httpx + structlog）。
M0~M5 已落地（含基线/异常检测引擎 v1、容器镜像 0.1.1、Salt 部署），41 个单测通过；agent 已在服务器消费生产 Stream（dry-run）。
剩余待办：配置 LLM 接口并切换 AGENT_DRY_RUN=0 上线写回、M4.4 可观测性验收、Redis Checkpoint 接入、基线引擎多窗口/多粒度演进（P2）。

---

## 范围外（后续另行规划）

- 大模型运行环境（llama.cpp / GGUF / 模型服务部署）
- 上线运维与周期自愈（schedule 示例见 salt/README，可随时启用）

## 风险与待确认

- Redis 内存预算：agent 新增键会占用现有 databus Redis（1gb allkeys-lru），代码按 TTL 与键量控制，部署阶段再定扩容方案
- 模型接口能力：本地边缘接口的 tool_calling / JSON 合规能力决定升级率，先按能力声明开发，实测后校准
- 云端 Provider 未定：先按 OpenAI 兼容抽象开发，配置留空即可跑本地闭环
- v1 范围（M0-C5）与基线引擎是否后置：建议后置，避免阻塞主链路
