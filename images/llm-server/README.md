# LLM Server 容器镜像（llama.cpp / llama-server）

数据总线提供的本地边缘 LLM 推理服务镜像。采用 [llama.cpp](https://github.com/ggml-org/llama.cpp)
的 `llama-server`，在**纯 CPU**（x86_64）环境以 OpenAI 兼容 API
（`/v1/chat/completions`）对外提供推理，供下游智能体/分析方消费
（本项目只输出数据源与推理服务，智能体本身不在本项目范围内）。

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
- **内置模型**：`Qwen3.8-2B-Q4_K_M.gguf`（约 1.31GB，Apache-2.0）已打包进镜像，
  构建时从 `empero-ai/Qwen3.8-2B-Distill-GGUF` 仓库下载 Q4_K_M 并做 SHA-256 校验；无需外挂模型目录即可运行。
  更换模型可挂载 `/models` 覆盖或改 `LLM_MODEL` 指向其他 GGUF。
- **现阶段线上默认选型**：`Qwen3.8-2B-Distill` 是当前数据总线线上默认的本地边缘 LLM
  （与 salt pillar `llm_server.model_alias` 一致），定位为"预筛 + 初判 + 结构化输出"
  的快速执行器，选型理由：Apache-2.0、工具调用能力可接受、模型与 KV 缓存合计约 1.1GB，
  在现网 10 核 / 23G 上余量充足。

## 文件清单

| 文件 | 说明 |
|---|---|
| `images/Dockerfile.llm-server` | 多阶段构建：编译 llama-server + Alpine 运行时 + 内置 Qwen3.8-2B-Distill 模型 |
| `images/llm-server/entrypoint.sh` | ENV → llama-server 参数映射入口 |
| `images/llm-server/scripts/fetch-model.sh` | 开发用：把备选 GGUF 下到本地（换模型时才用，镜像构建不依赖它） |

## 构建

镜像由 CI 构建（本地不构建、不上传）：

```bash
# push 到 main 即触发 .github/workflows/build-images.yml 的 llm-server job
# 产物：ghcr.io/cxiyuan/nss-ndr-public/llm-server:<tag>（镜像站 ghcr.nju.edu.cn 同步）
# 模型在构建期由 Dockerfile 从 HF 拉取并校验 SHA-256
```

> 服务器拉不动 ghcr.io 时，用 `scripts/fetch-all-images.sh` 在本机下载
> OCI/docker-save 包，再 `scripts/sync-salt.sh --with-images` 传过去 `docker load`。

AVX512-BF16（Cooper Lake / Zen4 / Sapphire Rapids）与 AMX（Sapphire Rapids）内核
已包含在多变体构建中，仅在对应硬件上被加载，无需额外参数。

## 运行

**线上由 Salt 管理**（`src/databus/salt/states/containers/llm-server.sls`），
参数经 `pillar databus.llm_server` 下发，端口不发布到宿主机、只在 nss-net 内
以 alias `llm-server` 暴露。手工起容器仅用于本地验证：

```bash
docker run -d --name llm-test \
  --network nss-net \
  -e LLM_CONTEXT_SIZE=16384 -e LLM_PARALLEL=1 \
  ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/llm-server:latest

# 冒烟（在 nss-net 内的容器里执行，如 salt-minion）
wget -qO- http://llm-server:8080/health
wget -qO- http://llm-server:8080/v1/models
```

> 覆盖内置模型：`-v /opt/nss/ndr/models:/models:ro -e LLM_MODEL=/models/model.gguf`

## 运行配置（环境变量）

| 环境变量 | 镜像默认 | 说明 |
|---|---|---|
| `LLM_MODEL` | `/models/Qwen3.8-2B-Q4_K_M.gguf` | GGUF 模型路径（内置） |
| `LLM_HOST` / `LLM_PORT` | `0.0.0.0` / `8080` | 监听地址 / 端口 |
| `LLM_ALIAS` | `Qwen3.8-2B-Distill` | API 返回的 model 名（与下游消费方约定保持一致） |
| `LLM_CONTEXT_SIZE` | `16384` | **总**上下文；`--parallel N` 时每个 slot 分到 `ctx/N`（要每 slot 16K 且 4 并发就得配 65536） |
| `LLM_CONTEXT_RATIO` | `0.75` | 再乘一次系数（`1.0` = 不缩水） |
| `LLM_PARALLEL` | `1` | 并发 slot（现网 4，由 salt pillar 下发） |
| `LLM_BATCH_SIZE` / `LLM_UBATCH_SIZE` | `1024` / `256` | 批处理大小 |
| `LLM_CACHE_TYPE_K/V` | `q8_0` | KV 缓存量化；追求精度可改 `f16`（内存翻倍） |
| `LLM_THREADS_RATIO` | `0.75` | 线程数 = 宿主机核数 × 该比例 |
| `LLM_API_KEY` | 空 | 开启 API Key 鉴权（与下游消费方 API Key 对应） |
| `LLM_EXTRA_ARGS` | 空 | 追加任意 llama-server 参数（如 `--mlock --numa distribute`） |

> 现网实际值由 salt pillar `databus.llm_server` 下发（见 `src/databus/salt/pillar.example`），
> 与本表默认值可能不同：当前为 `context_size=65536` / `parallel=4` /
> `extra_args="--reasoning off"`（关思考链，见下）。

## 关思考链（现网默认开启）

Qwen3 系列默认会先输出 `reasoning_content`（思考），把输出预算大量耗在推理上，
`content` 长时间为空（下游解析不到结果）。现网通过 salt pillar 下发：

```
extra_args: "--reasoning off"
```

实测效果：`reasoning_content` 为空、直接出正文，首 token 延迟 1.79s → **0.34s**，
同样 128 token 输出预算下有用正文从 ~130 字符提升到 ~630 字符（~4-5×）。

代价：事实类问题质量基本不变，但**分析/判断类任务质量会下降**（推理链正是
复杂判断的强项）。如需对特定请求恢复思考，可在请求体里带
`"chat_template_kwargs": {"enable_thinking": true}`。

## 与下游消费方对接

下游智能体/分析方通过 nss-net 内 alias `llm-server`（`http://llm-server:8080/v1`）
调用本服务。约定如下：

```bash
# 下游消费方（智能体侧）配置示例——不属本项目，由消费方自行维护
EDGE_LLM_BASE_URL=http://llm-server:8080/v1
EDGE_LLM_API_KEY=            # 与 LLM_API_KEY 一致；未开启鉴权可留空
EDGE_LLM_MODEL=Qwen3.8-2B-Distill
```

llama-server 不校验请求里的 `model` 字段，下游消费方模型名只需与 `LLM_ALIAS` 对应便于日志审计。

## 内存预算参考

- 模型权重（Qwen3.8-2B Q4_K_M）：约 1.31GB
- KV 缓存（q8_0）：按 `ctx-slots × tokens` 估算，现网四 slot 合计约 1-2GB（按需分配）
- 计算缓冲 / 运行开销：约 1~2GB
- 合计约 2~4GB 量级（现网宿主机 10 核 / 23G，余量充足）

## 模型备选（仅换 GGUF + 重启）

> 现状：**`Qwen3.8-2B-Distill` 是线上默认选型**（已内置）。本节给出后续如需升级/替换的备选清单。

- `Qwen3.8-2B-Distill`（**已内置，线上默认**，Apache-2.0，Q4_K_M 1.31GB，推理质量显著优于原 0.6B、内存占用适中）
- `xLAM-2-3b-fc-r`（Q4_K_M 约 1.93GB，工具调用更强）
- `Granite-4.1-3B`（Apache 2.0，131K 上下文，商用合规）

```bash
images/llm-server/scripts/fetch-model.sh xLAM-2-3B-fc-r-Q4_K_M.gguf
```

> **重要**：切换备选模型时务必同步修改以下两处，否则下游消费方无法正确路由：
> 1. `llm-server` 启动环境变量 `LLM_ALIAS`（决定 `/v1/models` 返回的 model 字段）
> 2. salt pillar `databus.llm_server.model_alias`（保持同步）

## 说明与限制

- 纯 CPU 2B 模型（当前线上默认 `Qwen3.8-2B-Distill`）推理速度受 CPU 限制，建议 /models 放 NVMe；
  定位为"预筛 + 初判 + 结构化输出"的快速执行器，
  复杂任务由下游消费方自行升级云端，不依赖本服务做深度分析。
- 模型已内置镜像（`/models/Qwen3.8-2B-Q4_K_M.gguf`，约 1.31GB），
  构建时从 HF 官方仓库下载并校验 SHA-256；挂载 `/models` 仍可覆盖或补充其他 GGUF。
