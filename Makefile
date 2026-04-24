TARGET  = evilginx
MODULE  = github.com/kgretzky/evilginx2
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
COMMIT  = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS = -ldflags "-X $(MODULE)/core.VERSION=$(VERSION) -X $(MODULE)/core.COMMIT=$(COMMIT)"

.PHONY: all build test vet fmt lint vuln clean

all: build

build:
	@mkdir -p ./build
	@go build $(LDFLAGS) -o ./build/$(TARGET) -mod=vendor main.go

test:
	@go test ./...

vet:
	@go vet ./...

fmt:
	@gofmt -l -w .

lint:
	@golangci-lint run ./...

vuln:
	@govulncheck ./...

clean:
	@go clean
	@rm -f ./build/$(TARGET)
