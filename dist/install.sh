#!/bin/bash

# 41Swara Smart Contract Scanner - Installation Script
# Supports Linux and macOS

set -e

REPO_URL="https://github.com/41swara/41Swara-tool"
VERSION="v1.0.0"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="41swara-scanner"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Detect operating system and architecture
detect_platform() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    case "$os" in
        Linux*)
            if [[ "$arch" == "x86_64" ]]; then
                PLATFORM="linux"
                BINARY_FILE="41swara-scanner-linux"
            else
                print_error "Unsupported architecture: $arch"
                exit 1
            fi
            ;;
        Darwin*)
            if [[ "$arch" == "x86_64" ]]; then
                PLATFORM="macos-intel"
                BINARY_FILE="41swara-scanner-macos-intel"
            elif [[ "$arch" == "arm64" ]]; then
                PLATFORM="macos-apple-silicon"
                BINARY_FILE="41swara-scanner-macos-arm64"
            else
                print_error "Unsupported architecture: $arch"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported operating system: $os"
            print_error "Please use the manual installation method"
            exit 1
            ;;
    esac
    
    print_status "Detected platform: $PLATFORM ($arch)"
}

# Check if running as root
check_permissions() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Installation will proceed to $INSTALL_DIR"
        SUDO_CMD=""
    else
        print_status "Checking if sudo is available for installation to $INSTALL_DIR"
        if command -v sudo >/dev/null 2>&1; then
            SUDO_CMD="sudo"
        else
            print_error "This script requires sudo access to install to $INSTALL_DIR"
            print_error "Please run: sudo $0"
            exit 1
        fi
    fi
}

# Check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check for required tools
    for tool in curl chmod; do
        if ! command -v $tool >/dev/null 2>&1; then
            print_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    print_success "All dependencies found"
}

# Download binary
download_binary() {
    local temp_dir=$(mktemp -d)
    local download_url
    
    # For this example, we'll use the local file
    # In production, this would be a real GitHub release URL
    if [[ -f "linux/41swara-scanner-linux" ]]; then
        print_status "Using local binary for installation"
        cp "linux/41swara-scanner-linux" "$temp_dir/$BINARY_NAME"
    else
        print_error "Binary not found. Please ensure the distribution files are available."
        exit 1
    fi
    
    TEMP_BINARY="$temp_dir/$BINARY_NAME"
    
    # Verify binary exists and is executable
    if [[ ! -f "$TEMP_BINARY" ]]; then
        print_error "Failed to download binary"
        exit 1
    fi
    
    chmod +x "$TEMP_BINARY"
    print_success "Binary downloaded and prepared"
}

# Install binary
install_binary() {
    print_status "Installing $BINARY_NAME to $INSTALL_DIR"
    
    # Create install directory if it doesn't exist
    $SUDO_CMD mkdir -p "$INSTALL_DIR"
    
    # Copy binary to install directory
    $SUDO_CMD cp "$TEMP_BINARY" "$INSTALL_DIR/$BINARY_NAME"
    
    # Ensure binary is executable
    $SUDO_CMD chmod +x "$INSTALL_DIR/$BINARY_NAME"
    
    print_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        local version_output=$($BINARY_NAME --help 2>&1 | head -1)
        print_success "Installation successful!"
        print_success "$version_output"
    else
        print_error "Installation verification failed"
        print_error "$INSTALL_DIR may not be in your PATH"
        print_warning "Try running: export PATH=\$PATH:$INSTALL_DIR"
        print_warning "Or run directly: $INSTALL_DIR/$BINARY_NAME"
        exit 1
    fi
}

# Show usage examples
show_usage() {
    echo ""
    echo -e "${BLUE}🚀 41Swara Scanner is now installed!${NC}"
    echo ""
    echo -e "${GREEN}Quick Start:${NC}"
    echo "  $BINARY_NAME --path MyContract.sol"
    echo "  $BINARY_NAME --path contracts/ --verbose"
    echo ""
    echo -e "${GREEN}Professional Audit Report:${NC}"
    echo "  $BINARY_NAME --audit --project \"MyProject\" --sponsor \"ClientName\" --path Contract.sol"
    echo ""
    echo -e "${GREEN}Get Help:${NC}"
    echo "  $BINARY_NAME --help"
    echo "  $BINARY_NAME --examples"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Create a test Solidity contract"
    echo "  2. Run the scanner to detect vulnerabilities"
    echo "  3. Review the security recommendations"
    echo ""
    echo -e "${BLUE}Documentation: https://github.com/41swara/41Swara-tool${NC}"
}

# Main installation process
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           41Swara Smart Contract Scanner                ║"
    echo "║              Installation Script v1.0.0                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    detect_platform
    check_permissions
    check_dependencies
    download_binary
    install_binary
    verify_installation
    show_usage
    
    print_success "Installation completed successfully! 🎉"
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 1' INT TERM

# Run main installation
main "$@"