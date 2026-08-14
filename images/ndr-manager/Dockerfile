# NSS-NDR Manager：统一配置管理后台（Web UI + API + 配置渲染/下发 + 规则管理）

# 阶段1：前端 SPA 构建
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ .
RUN npm run build

# 阶段2：Go 后端构建
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY images/ndr-manager/go.mod images/ndr-manager/go.sum ./
RUN go mod download
COPY images/ndr-manager/ .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /ndr-manager .

# 阶段3：pySigma 环境（Sigma 标准转换器，对齐 SO 做法）
FROM python:3.12-slim AS pysigma
RUN pip install --no-cache-dir sigma-cli pysigma-backend-elasticsearch

# 阶段4：运行镜像（python 运行时 + sigma + Go 二进制）
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=pysigma /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=pysigma /usr/local/bin/sigma /usr/local/bin/sigma
COPY --from=build /ndr-manager /usr/local/bin/ndr-manager
# Sigma 字段映射管道（pySigma processing pipeline）
COPY images/ndr-manager/sigma_so_pipeline.yaml /opt/ndr-manager/sigma_so_pipeline.yaml
# 内置规则集（so_extractions / so_filters，默认禁用）
COPY images/detections/builtin-rules/ /opt/so/builtin-rules/
# ET Open 内置规则集（35 个分类，约 3.9 万条，默认全部禁用，WebUI 勾选加载）
COPY images/ndr-manager/etopen/ /opt/so/etopen/
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ndr-manager"]
