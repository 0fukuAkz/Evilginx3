#!/bin/bash

#############################################################################
# Evilginx 3.3.1 - Test/Build-Only Mode
#############################################################################
# This script builds Evilginx without installing as a system service
# Perfect for testing on Windows WSL or development environments
#############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

GO_VERSION="1.22.0"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Evilginx 3.3.1 - Test Build Mode${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    log_error "Go is not installed!"
    log_info "Installing Go $GO_VERSION..."
    
    cd /tmp
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    export PATH=$PATH:/usr/local/go/bin
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    
    log_success "Go installed"
else
    log_success "Go already installed: $(go version)"
fi

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

log_info "Building from: $SCRIPT_DIR"

# Download dependencies
log_info "Downloading Go modules..."
go mod download

# Clean previous build
log_info "Cleaning previous build..."
rm -rf build/evilginx build/evilginx.exe

# Build
log_info "Compiling Evilginx..."
go build -o build/evilginx main.go

if [[ -f "build/evilginx" ]]; then
    chmod +x build/evilginx
    log_success "Build successful!"
    echo ""
    log_info "Binary location: $SCRIPT_DIR/build/evilginx"
    log_info "Phishlets: $SCRIPT_DIR/phishlets"
    log_info "Redirectors: $SCRIPT_DIR/redirectors"
    echo ""
    log_success "You can now run: sudo ./build/evilginx -p ./phishlets"
    echo ""
else
    log_error "Build failed!"
    exit 1
fi

