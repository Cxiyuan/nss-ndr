# nss-ndr-ollama

NDR 本地分析 Agent 用的 Ollama 服务镜像（纯 CPU 优化版）。

## 模型挂载（外挂 GGUF，不入镜像）

镜像**不**包含模型权重。运行时由 docker-compose 把宿主机目录挂到容器内的 `/models/`：

```yaml
volumes:
  - /opt/ndr/ollama-models:/models:ro
```

期望文件：`/opt/ndr/ollama-models/Qwen3-0.6B-Q5_K_M.gguf`

### 部署时自动准备 GGUF

`releases/deploy.sh install` 会按以下顺序查找 GGUF：

1. `images/ollama/models/Qwen3-0.6B-Q5_K_M.gguf`（仓库内、gitignored）
2. 项目根 `Qwen3-0.6B-Q5_K_M.gguf`

找到则自动拷到 `/opt/ndr/ollama-models/`，否则打印告警并继续（容器启动后 entrypoint 会因为找不到 GGUF 而进入待机循环，由运维排查）。

### 为什么外挂而非嵌入

- CI 不需要上传 424 MB 大文件（git / 镜像分层都变轻）
- 模型升级只需替换一个文件，无需重打镜像
- 多探针可共享同一份 GGUF（不同 mount 路径）

## 模型说明

- **qwen3-ndr**（基于 Qwen3-0.6B-Q5_K_M 量化）
  - 参数：~600 M
  - 量化：Q5_K_M（CPU 友好）
  - 上下文：4096 tokens
  - 输出上限：1024 tokens
  - 用途：研判类任务（"是否为真实威胁 / 是否为噪声"），输出中文结论 + 工具调用链证据

## CPU 优化

通过 entrypoint.sh 设置：

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `OLLAMA_HOST` | `0.0.0.0:11434` | 监听地址 |
| `OLLAMA_NUM_THREADS` | `nproc` | 线程数（自动匹配物理核数）|
| `OLLAMA_KEEP_ALIVE` | `24h` | 模型权重驻留内存 |
| `OLLAMA_MAX_LOADED_MODELS` | `1` | 单模型探针只加载一个 |
| `OLLAMA_WARMUP` | `1` | 启动时预热（避免首次推理卡顿）|
| `CUDA_VISIBLE_DEVICES` | `""` | 强制 CPU |
| `OLLAMA_NOHISTORY` | `1` | 关闭命令历史持久化 |

## 构建

```bash
# 本地构建（在项目根目录执行）
docker build -t ghcr.io/cxiyuan/nss-ndr/nss-ndr-ollama:latest \
    -f images/ollama/Dockerfile images/ollama

# 或经 GitHub Actions（推送 master 后自动触发）
# .github/workflows/build-images.yml 中添加 ollama 矩阵项
```

## 验证

```bash
# 列出已建模型
docker exec nss-ollama ollama list

# 健康检查
curl -sf http://localhost:11434/api/tags | jq

# 简单推理
curl -s http://localhost:11434/api/generate \
    -d '{"model":"qwen3-ndr","prompt":"你好","stream":false}' | jq '.response'
```

## 镜像大小

约 1.1 GB（Ollama 基础镜像 ~700 MB + Qwen3 GGUF ~424 MB + Modelfile + entrypoint）。

## 离线部署

`releases/save-images --include-base` 包含该项目镜像。本项目 2026-08-15 起 M11（Agent）
默认使用本镜像作为 LLM 后端（替换原 `host.docker.internal:11434` 的外部 Ollama 假设）。