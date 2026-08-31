# 深瞳安全分析智能体（nss-ndr-agent）

后台常驻的纯后端安全分析引擎：消费数据总线 Redis Stream `analysis:events`，
经规则引擎预聚合 + LangGraph 编排（本地/云端模型 + MCP 工具）产出结论，
写回 Redis（缓存/水位）与 ES（历史结论/事件）。

## 范围

- 只做智能体本身：模型接口为外部提供的 OpenAI 兼容 API（`config/providers.yaml` 配置）
- 容器镜像由 CI 构建并直接推送 GHCR：`ghcr.io/cxiyuan/nss-ndr-public/agent:<版本>`
- Salt 部署 / 模型运行环境不在本仓库当前范围（见 `TODO.md` 范围外）

## 目录

```text
app/           核心代码（schemas / rules / providers / mcp / pipeline / worker）
config/        agent.yaml + providers.yaml + rules/*.yaml
prompts/       提示词模板（系统/任务/输出约束）
skills/        场景化 Skills（SKILL.md，三层渐进式加载）
data/          资产知识库种子 CSV
tests/         单元测试（fake Redis/ES/LLM，目标机外可跑）
```

## 快速开始

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 配置模型接口（本地开发留空也能跑通"规则直接判定"分支）
cp config/providers.yaml config/providers.local.yaml   # 按需改 base_url/api_key/model

pytest                       # 单测
python -m app version        # 版本
python -m app worker         # 常驻消费（需要数据总线 Redis）
python -m app once           # 单批消费（调试）
```

## 环境变量（复用数据总线 /etc/nss-ndr/.env 键名）

| 变量 | 说明 |
|---|---|
| `REDIS_URL` / `REDIS_PASSWORD` | Redis 连接（Stream 消费） |
| `ELASTICSEARCH_HOSTS` / `ELASTICSEARCH_USERNAME` / `ELASTICSEARCH_PASSWORD` | ES 连接 |
| `EDGE_LLM_BASE_URL` / `EDGE_LLM_API_KEY` / `EDGE_LLM_MODEL` | 本地边缘模型接口（默认指向 `http://llm-server:8080/v1`，模型 `Qwen3-0.6B-Q8_0`） |
| `CLOUD_LLM_BASE_URL` / `CLOUD_LLM_API_KEY` / `CLOUD_LLM_MODEL` | 云端高阶模型接口 |
| `AGENT_DRY_RUN` | 1=只读消费（不写结论/不 XACK） |

## 核心链路

```
analysis:events (Redis Stream)
  → Worker 批处理（1000条/5s, XAUTOCLAIM 恢复）
  → 会话分组 → LangGraph: cache_lookup → aggregate → model(edge) → escalate_check
                                       → tool_loop(MCP) → cloud_model → verdict_write → alert
  → Redis agent:result:{sess}（原子写回, Lua）+ ES verdict/event 索引
```

详细设计见 `设计文档/安全分析智能体设计v05.docx`，开发计划见 `TODO.md`。

## 容器镜像

```bash
# 直接从 GHCR 拉取（推荐）
docker pull ghcr.io/cxiyuan/nss-ndr-public/agent:0.1.0

# 本地构建（可选；CI 已自动推送 GHCR）
images/scripts/build-agent.sh [版本]   # 仅产 tar，自行 docker load

# 运行（无 Redis 时优雅降级；对接生产需要 REDIS_URL / ELASTICSEARCH_HOSTS 等环境变量）
docker run --rm ghcr.io/cxiyuan/nss-ndr-public/agent:0.1.0 once
docker run --rm ghcr.io/cxiyuan/nss-ndr-public/agent:0.1.0 worker
```

> 自 2026-08-31 起不再发布 `.run` 自解压安装包与离线镜像 tar；
> 上线部署统一使用 `docker pull` + Salt 编排。
