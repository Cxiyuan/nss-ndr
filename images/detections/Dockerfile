# NSS-NDR detections 规则管理服务

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/detections .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -S nss && adduser -S -G nss nss
COPY --from=builder /out/detections /usr/local/bin/detections
COPY builtin-rules/ /opt/so/builtin-rules/
RUN chown -R nss:nss /opt/so/builtin-rules
# M2 暂以 root 运行以便写入共享 hostPath（/opt/so/rules、/opt/so/state、/var/run/suricata）
# 后续按需收紧为特定 uid
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/detections"]
