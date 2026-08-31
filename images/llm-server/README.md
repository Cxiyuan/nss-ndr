# LLM Server 容器镜像（llama.cpp / llama-server）

深瞳安全分析智能体的本地边缘 LLM 服务镜像。采用 [llama.cpp](https://github.com/ggml-org/llama.cpp)
的 `llama-server`，在**纯 CPU**（x86_64）环境以 OpenAI 兼容 API
（`/v1/chat/completions`）对外提供推理，供智能体 `providers.yaml` 的 edge Provider 对接
（设计文档 §2 / §8 / §15）。

## 设计要点

- **纯 CPU + AVX512**：关闭 CUDA/Metal/BLAS 等加速后端；采用 llama.cpp CPU 后端
  **多变体机制**（`GGML_CPU_ALL_VARIANTS`，与上游官方 CPU 镜像同款方案）——
  编译 x64 基线 + SSE42→AVX2→AVX512（Skylake-X/Cascade/Ice/Cooper/Zen4/Sapphire
  Rapids）全套后端 `.so`，`llama-server` 主程序保持基线指令集，启动时按 CPUID 选出
  最高分变体加载：AVX512 机器用满 AVX512（含 VNNI/VBMI/BF16/AMX），仅 AVX2 机器
  自动回退 haswell 变体，无需重编、不会 SIGILL。
- **轻量镜像**：Alpine（musl）+ 动态链接（运行期仅 libstdc++/libgcc/libgomp），
  镜像约 200MB 量级，不依赖宿主 glibc。
- **可复现**：llama.cpp 固定 tag `b10681`（`Dockerfile` 内 `ARG LLAMA_CPP_TAG`）。
- **内置模型**：`Qwen3-0.6B-Q8_0.gguf`（约 624MB，Apache-2.0）已打包进镜像，
  构建时从官方 `Qwen/Qwen3-0.6B-GGUF` 仓库下载并做 SHA-256 校验；无需外挂模型目录即可运行。
  更换模型可挂载 `/models` 覆盖或改 `LLM_MODEL` 指向其他 GGUF。
- **现阶段线上默认选型**：`Qwen3-0.6B-Q8_0` 是当前 NSS-NDR 项目线上默认的本地边缘 LLM
  （与 agent `EDGE_LLM_MODEL=Qwen3-0.6B-Q8_0`、salt pillar `llm_server.model_alias` 一致）。
  设计文档 §8 把它定位为"预筛 + 初判 + 结构化输出"的快速执行器，复杂任务由 agent 网关升级云端，
  选型理由：Apache-2.0、工具调用能力可接受、模型与 KV 缓存合计约 1.1GB，
  在 6C/12G 预算内仍能给 baseline / MCP 工具留足余地。

## 文件清单

| 文件 | 说明 |
|---|---|
| `images/Dockerfile.llm-server` | 多阶段构建：编译 llama-server + Alpine 运行时 + 内置 Qwen3-0.6B-Q8_0 模型 |
| `images/llm-server/entrypoint.sh` | ENV → llama-server 参数映射入口 |
| `images/llm-server/scripts/fetch-model.sh` | 下载 GGUF 到 `offline/models/` |
| `images/scripts/build-llm-server.sh` | 构建 + 校验 + 导出离线 tar |
| `images/offline/nss-ndr_llm-server_<版本>.tar` | 离线镜像产物（Salt load） |

## 构建

```bash
# 构建镜像 + 导出 offline tar（默认版本 0.1.0；模型由 Dockerfile 构建时自动下载）
images/scripts/build-llm-server.sh [版本]

# 产物：images/offline/nss-ndr_llm-server_0.1.0.tar
# 镜像：nss-ndr/llm-server:0.1.0（含 /models/Qwen3-0.6B-Q8_0.gguf）
```

> 如需离线构建，可先执行 `images/llm-server/scripts/fetch-model.sh` 把模型放到
> `images/offline/models/`，再用 `docker build` 时挂载或手动 COPY 进镜像。

AVX512-BF16（Cooper Lake / Zen4 / Sapphire Rapids）与 AMX（Sapphire Rapids）内核
已包含在多变体构建中，仅在对应硬件上被加载，无需额外参数。

## 运行

```bash
# 默认模型已内置镜像，直接运行即可（无需挂载模型目录）
docker run -d --name nss-ndr-llm-server \
  --restart unless-stopped \
  -p 8080:8080 \
  -e LLM_CONTEXT_SIZE=32768 \
  -e LLM_THREADS=6 \
  nss-ndr/llm-server:0.1.0

# 冒烟：等待 /health 返回 200 后
curl http://127.0.0.1:8080/v1/models
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"Qwen3-0.6B-Q8_0","messages":[{"role":"user","content":"ping"}],"max_tokens":16}'
```

> 若需覆盖内置模型：`-v /opt/nss-ndr/models:/models:ro -e LLM_MODEL=/models/model.gguf`

## 运行配置（环境变量）

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `LLM_MODEL` | `/models/Qwen3-0.6B-Q8_0.gguf` | GGUF 模型路径（内置） |
| `LLM_HOST` / `LLM_PORT` | `0.0.0.0` / `8080` | 监听地址 / 端口 |
| `LLM_ALIAS` | `Qwen3-0.6B-Q8_0` | API 返回的 model 名（与 agent `EDGE_LLM_MODEL` 保持一致） |
| `LLM_CONTEXT_SIZE` | `32768` | 上下文窗口（设计文档 §4 预算：32K） |
| `LLM_PARALLEL` | `1` | 并发 slot（6C/12G 预算建议保持 1） |
| `LLM_BATCH_SIZE` / `LLM_UBATCH_SIZE` | `2048` / `512` | 批处理大小 |
| `LLM_CACHE_TYPE_K/V` | `q8_0` | KV 缓存量化：32K 上下文下省约一半缓存内存；追求精度可改 `f16` |
| `LLM_THREADS` | 空（自动） | 推理线程数，建议 ≤ 分配核数，如 `6` |
| `LLM_API_KEY` | 空 | 开启 API Key 鉴权（与 agent `EDGE_LLM_API_KEY` 对应） |
| `LLM_EXTRA_ARGS` | 空 | 追加任意 llama-server 参数（如 `--mlock --numa distribute`） |

## 与智能体对接

在 `/etc/nss-ndr/.env`（Salt 环境）填入并重建 agent 容器：

```bash
EDGE_LLM_BASE_URL=http://llm-server:8080/v1
EDGE_LLM_API_KEY=            # 与 LLM_API_KEY 一致；未开启鉴权可留空
EDGE_LLM_MODEL=Qwen3-0.6B-Q8_0
AGENT_DRY_RUN=0
```

llama-server 不校验请求里的 `model` 字段，agent 侧模型名只需与 `LLM_ALIAS` 对应便于日志审计。

## 内存预算参考（6C/12G 专属环境，设计文档 §8）

- 模型权重（Qwen3-0.6B Q8_0）：约 0.6GB
- KV 缓存（32K 上下文，q8_0）：约 0.5GB
- 计算缓冲 / 运行开销：约 1~2GB
- 合计约 2~3GB 量级，12G 预算内可再加 `LLM_CONTEXT_SIZE` 或并发 slot

## 模型备选（设计文档 §8.5，仅换 GGUF + 重启）

> 现状：**`Qwen3-0.6B-Q8_0` 是线上默认选型**（已内置）。本节给出后续如需升级/替换的备选清单。

- `Qwen3-0.6B-Q8_0`（**已内置，线上默认**，Apache-2.0，0.6B / Q8_0，工具调用好、内存占用低）
- `xLAM-2-3b-fc-r`（Q4_K_M 约 1.93GB，工具调用更强）
- `Granite-4.1-3B`（Apache 2.0，131K 上下文，商用合规）

```bash
images/llm-server/scripts/fetch-model.sh xLAM-2-3B-fc-r-Q4_K_M.gguf
```

> **重要**：切换备选模型时务必同步修改以下三处，否则 agent 无法正确路由：
> 1. `llm-server` 启动环境变量 `LLM_ALIAS`（决定 `/v1/models` 返回的 model 字段）
> 2. agent `providers.yaml` 的 `edge.model`（通过 `.env` 的 `EDGE_LLM_MODEL` 注入）
> 3. salt pillar `databus.llm_server.model_alias`（保持同步）

## 说明与限制

- 纯 CPU 0.6B 模型（**当前线上默认 `Qwen3-0.6B-Q8_0`**）推理速度有限，
  设计文档定位其为"预筛 + 初判 + 结构化输出"的快速执行器，
  复杂任务由 agent 网关升级云端（`needs_cloud`），不依赖本服务做深度分析。
- 模型已内置镜像（`/models/Qwen3-0.6B-Q8_0.gguf`，约 624MB），
  构建时从 HF 官方仓库下载并校验 SHA-256；挂载 `/models` 仍可覆盖或补充其他 GGUF。
