TARGET  = evilginx
MODULE  = github.com/kgretzky/evilginx2
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
COMMIT  = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS = -ldflags "-X $(MODULE)/core.VERSION=$(VERSION) -X $(MODULE)/core.COMMIT=$(COMMIT)"

.PHONY: all build test vet fmt lint vuln audit clean keygen licensegen

all: build

# admin.key is a real file target: make only runs this rule when the file is absent.
# Re-running keygen would rotate the key pair and invalidate all issued licenses.
admin.key:
	@echo "No admin.key found — generating license key pair (first-time setup)..."
	@go run tools/keygen/main.go .

build: admin.key
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

audit:
	@go mod verify
	@govulncheck ./...

clean:
	@go clean
	@rm -f ./build/$(TARGET)

keygen:
	@go run tools/keygen/main.go .

licensegen:
	@mkdir -p ./build
	@go build -o ./build/licensegen tools/licensegen/main.go
