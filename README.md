# NSS-NDR 数据总线

NDR（网络检测与响应）数据总线。负责把 Zeek 解析的 43 类网络日志采集、归一化后写入
Elasticsearch，并生产可供下游智能体/分析方消费的数据源（Redis Stream）。

> **项目边界**：本项目只关注**数据总线**本身，输出数据源给下游智能体消费；
> 智能体（分析引擎/Agent）**不在本项目范围内**。本项目仅额外提供一个本地边缘
> LLM 推理服务容器（`llm-server`，内置 `Qwen3-0.6B-Q8_0`），作为数据源输出侧的模型服务。

## 数据流

```
网络流量
  └─ zeek 8.2.2（43 类日志 JSON 输出）
       ├─ elastic-agent（Zeek Integration 5.0.1）→ elasticsearch（ECS 字段归一化）
       └─ logstash → redis stream（analysis:events，供下游智能体消费）
llm-server（llama.cpp + Qwen3-0.6B-Q8_0，OpenAI 兼容 /v1）—— 本地边缘 LLM 推理服务
```

## 目录结构

```text
├── src/databus/            # 数据总线：zeek 配置 / logstash pipeline / Salt 编排
│   ├── zeek/               # local.zeek + 自定义检测脚本
│   ├── logstash/           # zeek → redis 双写 pipeline
│   ├── redis/              # redis 配置（stream: analysis:events）
│   ├── elastic-agent/      # Fleet Server 侧 elastic-agent 配置
│   └── salt/               # Salt state/pillar/scripts（容器编排与部署）
├── images/                 # 镜像构建（Dockerfile + entrypoint）
│   ├── Dockerfile.zeek-custom / .elastic-agent-zeek / .logstash-databus / .redis-databus / .elasticsearch / .kibana
│   ├── Dockerfile.llm-server + llm-server/   # 本地边缘 LLM 推理服务
│   ├── Dockerfile.salt-master-api / .salt-minion
│   └── zeek-integration/   # Zeek Integration 5.0.1 包（Elastic Agent 采集）
├── docs/                   # 开发/发布流程等说明
└── .github/workflows/      # CI（构建并推送数据总线相关镜像到 GHCR）
```

## 核心组件

| 组件 | 镜像 | 说明 |
|---|---|---|
| Zeek | `zeek-databus:8.2.2` | 协议解析，输出 43 类 JSON 日志 |
| Elasticsearch | `elasticsearch:9.5.2` | 日志落地（`.ds-logs-zeek.*`） |
| Kibana | `kibana:9.5.2` | 检索/管理（含 Fleet） |
| Fleet Server / Elastic Agent | `elastic-agent-zeek:9.5.2` | 采集 Zeek 日志入 ES（Zeek Integration 5.0.1，43 datasets） |
| Logstash | `logstash-databus:9.5.2` | zeek → redis 双写（供下游消费） |
| Redis | `redis-databus:8.10.1` | 数据源队列（stream: `analysis:events`） |
| LLM Server | `llm-server` | llama.cpp + Qwen3-0.6B-Q8_0，OpenAI 兼容推理服务 |
| Salt Master + Minion | `salt-master-api` / `salt-minion` | 容器化部署编排 |

## 构建与部署

- 镜像构建：`.github/workflows/build-images.yml`（推送到 GHCR `nss-ndr-public/*`）
- 容器编排：`src/databus/salt/`（Salt state + pillar，详见 `src/databus/salt/README.md`）
- 开发/发布流程铁律：见 `docs/deploy-process.md`
