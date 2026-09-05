# ==========================================
# 阶段 1: 静态编译 Go 二进制 (支持高速多平台交叉编译)
# ==========================================
FROM --platform=$BUILDPLATFORM golang:1-bookworm AS builder

ENV GOTOOLCHAIN=auto
WORKDIR /src

# 利用 Docker 缓存机制预下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制全部源码
COPY . .

# 编译静态二进制文件（零外部 CGO 依赖，支持 amd64/arm64 交叉编译）
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.0
ARG GIT_COMMIT=docker
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /app/warp-proxy \
    ./cmd/warp-proxy

# ==========================================
# 阶段 2: 运行时精简环境
# ==========================================
FROM debian:bookworm-slim

LABEL maintainer="hepengcheng@bytedance.com"
LABEL description="High-performance SOCKS5 proxy for Cloudflare WARP with transparent L4 forwarding"

ENV DEBIAN_FRONTEND=noninteractive

# 安装基础依赖及 Cloudflare 官方客户端源
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gpg \
        dbus \
        tzdata \
    && mkdir -p /usr/share/keyrings \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflare-warp \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 创建必要的运行目录
RUN mkdir -p /var/run/dbus /var/lib/cloudflare-warp /var/run/cloudflare-warp \
    && dbus-uuidgen --ensure=/etc/machine-id

# 从阶段 1 复制已编译好的单一管理二进制
COPY --from=builder /app/warp-proxy /usr/local/bin/warp-proxy

# 暴露端口：1080 (SOCKS5 代理), 8080 (HTTP 健康检查与指标状态)
EXPOSE 1080 8080

# 持久化挂载目录（保留 WARP 注册凭证与设备身份）
VOLUME ["/var/lib/cloudflare-warp"]

# 使用 warp-proxy 原生内置探针执行真实网络健康检查
# 无需容器内额外调用 curl，直接通过 SOCKS5 代理探测 Cloudflare 官方 trace
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/warp-proxy", "-healthcheck"]

# Go 主管程序作为 PID 1 启动
ENTRYPOINT ["/usr/local/bin/warp-proxy"]
