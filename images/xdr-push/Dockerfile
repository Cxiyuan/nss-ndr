# NSS-NDR xdr-push 告警推送服务

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/xdr-push .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -S nss && adduser -S -G nss nss
COPY --from=builder /out/xdr-push /usr/local/bin/xdr-push
RUN mkdir -p /opt/so/state && chown -R nss:nss /opt/so/state
# M2 暂以 root 运行以便写入共享 hostPath（/opt/so/state）
ENTRYPOINT ["/usr/local/bin/xdr-push"]
