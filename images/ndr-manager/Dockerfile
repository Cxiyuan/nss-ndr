# NSS-NDR Manager：统一配置管理后台（Web UI + API + 配置渲染/下发 + 规则管理）

# 阶段1：前端 SPA 构建
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ .
RUN npm run build

# 阶段2：Go 后端构建
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY images/ndr-manager/go.mod images/ndr-manager/go.sum ./
RUN go mod download
COPY images/ndr-manager/ .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /ndr-manager .

# 阶段3：运行镜像
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /ndr-manager /usr/local/bin/ndr-manager
# 内置规则集（so_extractions / so_filters，默认禁用）
COPY images/detections/builtin-rules/ /opt/so/builtin-rules/
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ndr-manager"]
