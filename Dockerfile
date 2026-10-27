# ==========================================
# 阶段 1: 静态编译 Go 二进制 (支持高速多平台交叉编译)
# ==========================================
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS builder

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
ARG VERSION=2.0.0-dev
ARG GIT_COMMIT=docker
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /app/warp-proxy \
    ./cmd/warp-proxy

# ==========================================
# 阶段 2: 运行时环境（静态二进制 + CA 证书，无 shell、无包管理器）
# ==========================================
# WireGuard 隧道由内核（或 /dev/net/tun 上的 wireguard-go）承载，镜像中不再包含官方 warp-svc。
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

LABEL maintainer="riba2534@qq.com"
LABEL description="Lightweight SOCKS5/HTTP proxy for Cloudflare WARP over WireGuard"

# 从阶段 1 复制已编译好的单一管理二进制
COPY --from=builder /app/warp-proxy /usr/local/bin/warp-proxy

# 暴露端口：1080 (SOCKS5 / SOCKS4 / HTTP CONNECT 代理), 8080 (HTTP 健康检查与指标状态)
EXPOSE 1080 8080

# 持久化挂载目录（保留 WARP 注册凭证与设备身份）
VOLUME ["/var/lib/cloudflare-warp"]

# 使用 warp-proxy 原生内置探针执行真实网络健康检查
# 无需容器内额外调用 curl，直接通过本地代理探测 Cloudflare 官方 trace
HEALTHCHECK --interval=30s --timeout=6s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/warp-proxy", "-healthcheck"]

# Go 主管程序作为 PID 1 启动
ENTRYPOINT ["/usr/local/bin/warp-proxy"]
