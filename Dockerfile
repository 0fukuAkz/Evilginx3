# Build Stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN go build -o evilginx .

# Runtime Stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/evilginx .

# Global directory for config
RUN mkdir -p /root/.evilginx
VOLUME ["/root/.evilginx"]

# Ports: DNS (53), HTTP (80), HTTPS (443)
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

ENTRYPOINT ["./evilginx"]
# Default command (can be overridden)
CMD ["-p", "/root/.evilginx/phishlets"]
