# Build Stage
FROM golang:1.24-alpine AS builder

# Install build dependencies (gcc + musl-dev + sqlite-dev required for CGo / go-sqlite3)
RUN apk add --no-cache git make gcc musl-dev sqlite-dev

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build with CGo enabled (required for go-sqlite3 driver)
COPY . .
RUN CGO_ENABLED=1 go build -o evilginx .

# Runtime Stage
FROM alpine:latest

# Install runtime dependencies (sqlite-libs needed by CGo-linked go-sqlite3)
RUN apk add --no-cache ca-certificates tzdata sqlite-libs

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/evilginx .

# Copy phishlets and redirectors
COPY --from=builder /app/phishlets ./phishlets
COPY --from=builder /app/redirectors ./redirectors

# Global directory for config
RUN mkdir -p /root/.evilginx
VOLUME ["/root/.evilginx"]

# Ports: DNS (53), HTTP (80), HTTPS (443)
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

ENTRYPOINT ["./evilginx"]
# Default command with correct paths
CMD ["-p", "/root/phishlets", "-t", "/root/redirectors", "-c", "/root/.evilginx"]
