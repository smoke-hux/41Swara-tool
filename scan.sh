#!/bin/bash

# Smart Contract Vulnerability Scanner - Helper Script
# Makes it easier to run the scanner with common options

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/target/release/solidity_scanner"

# Check if the scanner is built
if [ ! -f "$SCANNER" ]; then
    echo "🔨 Building scanner (first time setup)..."
    cd "$SCRIPT_DIR"
    cargo build --release --quiet
    if [ $? -ne 0 ]; then
        echo "❌ Build failed. Please check your Rust installation."
        exit 1
    fi
    echo "✅ Scanner built successfully!"
fi

# Function to show usage
show_usage() {
    echo "🔍 Smart Contract Vulnerability Scanner - Helper Script"
    echo "====================================================="
    echo
    echo "Usage: $0 [OPTIONS] <FILE_OR_DIRECTORY>"
    echo
    echo "Options:"
    echo "  -v, --verbose     Enable verbose output"
    echo "  -j, --json        Output in JSON format"
    echo "  -r, --report      Generate clean PDF-style report"
    echo "  -o, --output FILE Save report to file"
    echo "  -h, --help        Show this help"
    echo "  --examples        Show usage examples"
    echo
    echo "Examples:"
    echo "  $0 MyContract.sol"
    echo "  $0 --verbose contracts/"
    echo "  $0 --json --output report.json MyContract.sol"
    echo
}

# Parse arguments
VERBOSE=""
FORMAT="text"
OUTPUT=""
FILE=""
REPORT_MODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        -j|--json)
            FORMAT="json"
            shift
            ;;
        -r|--report)
            REPORT_MODE="--report"
            shift
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        --examples)
            "$SCANNER" --examples
            exit 0
            ;;
        -*)
            echo "❌ Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            FILE="$1"
            shift
            ;;
    esac
done

# Check if file/directory is provided
if [ -z "$FILE" ]; then
    echo "❌ Error: Please provide a file or directory to scan"
    echo
    show_usage
    exit 1
fi

# Build command
CMD="$SCANNER --path \"$FILE\" --format $FORMAT $VERBOSE $REPORT_MODE"

# Execute
if [ -n "$OUTPUT" ]; then
    echo "📄 Saving report to: $OUTPUT"
    eval $CMD > "$OUTPUT"
    echo "✅ Report saved successfully!"
else
    eval $CMD
fi