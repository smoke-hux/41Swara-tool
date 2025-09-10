#!/bin/bash

# 41Swara Smart Contract Scanner - Wrapper Script
# Version 1.0.0
# This script provides a convenient wrapper for the 41Swara scanner with enhanced features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_VERSION="1.0.0"
BINARY_NAME="41swara-scanner"
SCANNER_BINARY=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Print colored output functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              41Swara Smart Contract Scanner               ║${NC}"
    echo -e "${BLUE}║                   Shell Wrapper v${SCRIPT_VERSION}                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Find scanner binary
find_scanner() {
    # Check if binary is in PATH
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        SCANNER_BINARY="$BINARY_NAME"
        print_success "Found scanner in PATH: $(which $BINARY_NAME)"
        return 0
    fi
    
    # Check local binary
    if [[ -x "./target/release/solidity_scanner" ]]; then
        SCANNER_BINARY="./target/release/solidity_scanner"
        print_success "Found local scanner binary: $SCANNER_BINARY"
        return 0
    fi
    
    # Check current directory
    if [[ -x "./$BINARY_NAME" ]]; then
        SCANNER_BINARY="./$BINARY_NAME"
        print_success "Found scanner in current directory: $SCANNER_BINARY"
        return 0
    fi
    
    print_error "41Swara scanner not found!"
    print_info "Please ensure the scanner is installed or available in:"
    print_info "  - System PATH (run: which $BINARY_NAME)"
    print_info "  - Current directory: ./$BINARY_NAME"
    print_info "  - Build directory: ./target/release/solidity_scanner"
    exit 1
}

# Show usage information
show_usage() {
    echo -e "${CYAN}USAGE:${NC}"
    echo "  $0 [OPTIONS] <CONTRACT_PATH>"
    echo ""
    echo -e "${CYAN}OPTIONS:${NC}"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -f, --format FORMAT     Output format (text|json) [default: text]"
    echo "  -o, --output FILE       Save output to file"
    echo "  -r, --report            Generate clean PDF-style report"
    echo "  -a, --audit             Generate professional audit report"
    echo "  -p, --project NAME      Project name for audit report"
    echo "  -s, --sponsor NAME      Sponsor name for audit report"
    echo "  --quick                 Quick scan (basic output only)"
    echo "  --batch                 Batch mode (scan multiple files/directories)"
    echo "  --examples              Show scanner usage examples"
    echo ""
    echo -e "${CYAN}EXAMPLES:${NC}"
    echo "  # Basic scan"
    echo "  $0 MyContract.sol"
    echo ""
    echo "  # Verbose scan with output to file"
    echo "  $0 --verbose --output scan_results.txt contracts/"
    echo ""
    echo "  # Professional audit report"
    echo "  $0 --audit --project \"DeFi Protocol\" --sponsor \"Security Firm\" Token.sol"
    echo ""
    echo "  # Batch scan multiple contracts"
    echo "  $0 --batch Contract1.sol Contract2.sol contracts/"
    echo ""
    echo "  # JSON output for CI/CD"
    echo "  $0 --format json --output results.json contracts/"
}

# Quick scan function
quick_scan() {
    local path="$1"
    print_step "Running quick scan on: $path"
    "$SCANNER_BINARY" --path "$path"
}

# Batch scan function
batch_scan() {
    print_step "Starting batch scan mode"
    local total_files=0
    local total_issues=0
    
    for path in "$@"; do
        if [[ -f "$path" ]] || [[ -d "$path" ]]; then
            print_info "Scanning: $path"
            echo "----------------------------------------"
            "$SCANNER_BINARY" --path "$path" --format json > "/tmp/41swara_batch_${TIMESTAMP}_$(basename "$path").json" 2>/dev/null || true
            ((total_files++))
            echo ""
        else
            print_warning "Skipping non-existent path: $path"
        fi
    done
    
    print_success "Batch scan completed: $total_files files processed"
    print_info "Results saved to /tmp/41swara_batch_${TIMESTAMP}_*.json"
}

# Professional audit with enhanced output
professional_audit() {
    local path="$1"
    local project="$2"
    local sponsor="$3"
    local output_file="$4"
    
    print_step "Generating professional audit report"
    print_info "Project: $project"
    print_info "Sponsor: $sponsor"
    print_info "Target: $path"
    
    local cmd_args=(--audit --path "$path")
    [[ -n "$project" ]] && cmd_args+=(--project "$project")
    [[ -n "$sponsor" ]] && cmd_args+=(--sponsor "$sponsor")
    
    if [[ -n "$output_file" ]]; then
        "$SCANNER_BINARY" "${cmd_args[@]}" > "$output_file"
        print_success "Professional audit report saved to: $output_file"
    else
        "$SCANNER_BINARY" "${cmd_args[@]}"
    fi
}

# Enhanced scan with pre-checks
enhanced_scan() {
    local path="$1"
    local verbose="$2"
    local format="$3"
    local output_file="$4"
    local report_mode="$5"
    
    # Pre-scan validation
    print_step "Performing pre-scan validation"
    
    if [[ ! -e "$path" ]]; then
        print_error "Path does not exist: $path"
        exit 1
    fi
    
    if [[ -f "$path" ]]; then
        if [[ "$path" != *.sol ]]; then
            print_warning "File does not have .sol extension: $path"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
        print_info "Target: Single file - $(basename "$path")"
    elif [[ -d "$path" ]]; then
        local sol_count=$(find "$path" -name "*.sol" -type f | wc -l)
        print_info "Target: Directory with $sol_count .sol files"
        if [[ $sol_count -eq 0 ]]; then
            print_warning "No .sol files found in directory: $path"
        fi
    fi
    
    # Build command
    local cmd_args=(--path "$path")
    [[ "$verbose" == "true" ]] && cmd_args+=(--verbose)
    [[ -n "$format" ]] && cmd_args+=(--format "$format")
    [[ "$report_mode" == "true" ]] && cmd_args+=(--report)
    
    # Execute scan
    print_step "Starting vulnerability scan"
    if [[ -n "$output_file" ]]; then
        "$SCANNER_BINARY" "${cmd_args[@]}" > "$output_file"
        print_success "Scan results saved to: $output_file"
        
        # Show summary if text format
        if [[ "$format" != "json" ]]; then
            echo ""
            print_info "Scan summary:"
            tail -10 "$output_file"
        fi
    else
        "$SCANNER_BINARY" "${cmd_args[@]}"
    fi
}

# Parse command line arguments
parse_args() {
    local verbose="false"
    local format=""
    local output_file=""
    local report_mode="false"
    local audit_mode="false"
    local project=""
    local sponsor=""
    local quick_mode="false"
    local batch_mode="false"
    local paths=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_header
                show_usage
                exit 0
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -f|--format)
                format="$2"
                if [[ "$format" != "text" && "$format" != "json" ]]; then
                    print_error "Invalid format: $format. Use 'text' or 'json'"
                    exit 1
                fi
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -r|--report)
                report_mode="true"
                shift
                ;;
            -a|--audit)
                audit_mode="true"
                shift
                ;;
            -p|--project)
                project="$2"
                shift 2
                ;;
            -s|--sponsor)
                sponsor="$2"
                shift 2
                ;;
            --quick)
                quick_mode="true"
                shift
                ;;
            --batch)
                batch_mode="true"
                shift
                ;;
            --examples)
                "$SCANNER_BINARY" --examples
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                paths+=("$1")
                shift
                ;;
        esac
    done
    
    # Validate arguments
    if [[ ${#paths[@]} -eq 0 ]]; then
        print_error "No contract path specified"
        show_usage
        exit 1
    fi
    
    if [[ "$audit_mode" == "true" ]]; then
        if [[ ${#paths[@]} -gt 1 ]]; then
            print_error "Audit mode supports only one contract path"
            exit 1
        fi
        professional_audit "${paths[0]}" "$project" "$sponsor" "$output_file"
    elif [[ "$quick_mode" == "true" ]]; then
        quick_scan "${paths[0]}"
    elif [[ "$batch_mode" == "true" ]]; then
        batch_scan "${paths[@]}"
    else
        if [[ ${#paths[@]} -gt 1 ]]; then
            print_warning "Multiple paths specified. Use --batch for batch processing."
            print_info "Processing first path only: ${paths[0]}"
        fi
        enhanced_scan "${paths[0]}" "$verbose" "$format" "$output_file" "$report_mode"
    fi
}

# Main execution
main() {
    print_header
    
    # Find scanner binary
    find_scanner
    
    # Parse and execute
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    parse_args "$@"
}

# Execute main function
main "$@"