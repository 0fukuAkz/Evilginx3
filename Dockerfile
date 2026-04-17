# Build Stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy source (includes vendor directory for reproducible builds)
COPY . .

# Build (pure Go — no CGo or C compiler required)
RUN CGO_ENABLED=0 go build -mod=vendor -o evilginx .

# Runtime Stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/evilginx .

# Copy phishlets, redirectors, post_redirectors, web UI, and GoPhish static files
COPY --from=builder /app/phishlets ./phishlets
COPY --from=builder /app/redirectors ./redirectors
COPY --from=builder /app/post_redirectors ./post_redirectors
COPY --from=builder /app/web ./web
COPY --from=builder /app/gophish/static ./static

# Global directory for config
RUN mkdir -p /root/.evilginx
VOLUME ["/root/.evilginx"]

# Ports: DNS (53), HTTP (80), HTTPS (443), Admin API (2030), GoPhish Admin (3333)
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 2030/tcp 3333/tcp

ENTRYPOINT ["./evilginx"]
# Default command with correct paths
CMD ["-p", "/root/phishlets", "-t", "/root/redirectors", "-u", "/root/post_redirectors", "-c", "/root/.evilginx"]
