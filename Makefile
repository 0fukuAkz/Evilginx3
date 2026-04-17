TARGET=evilginx
VERSION ?= $(shell grep 'EVILGINX_VERSION=' install.sh 2>/dev/null | head -1 | cut -d'"' -f2)
ifeq ($(VERSION),)
  VERSION=dev
endif
PACKAGES=core database log parser

.PHONY: all build clean release release-linux

all: build

build:
	@CGO_ENABLED=0 go build -o ./build/$(TARGET) -mod=vendor main.go

# Cross-compile release binaries for Linux (amd64 + arm64)
release-linux:
	@mkdir -p ./build/release
	@echo "Building linux/amd64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath \
		-ldflags="-s -w" -o ./build/release/$(TARGET)-linux-amd64 main.go
	@echo "Building linux/arm64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -trimpath \
		-ldflags="-s -w" -o ./build/release/$(TARGET)-linux-arm64 main.go
	@echo "Computing checksums..."
	@cd ./build/release && shasum -a 256 $(TARGET)-linux-* > checksums.txt
	@echo "Release binaries in ./build/release/"
	@ls -lh ./build/release/

# Build release binaries for all supported platforms
release: release-linux

clean:
	@go clean
	@rm -rf ./build/$(TARGET) ./build/release
