# NSS-NDR cleaner 数据清理服务（CronJob）

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cleaner .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/cleaner /usr/local/bin/cleaner
COPY files/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
