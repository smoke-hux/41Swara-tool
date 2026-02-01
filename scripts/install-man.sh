#!/bin/bash
# Install man pages for 41Swara Smart Contract Scanner
# Run with: sudo ./scripts/install-man.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MAN_SOURCE="$PROJECT_DIR/man"
MAN_DEST="/usr/local/share/man/man1"

echo "41Swara Smart Contract Scanner - Man Page Installation"
echo "======================================================="

# Check if running as root for system-wide install
if [ "$EUID" -ne 0 ]; then
    echo "Note: Running without root. Installing to ~/.local/share/man/man1"
    MAN_DEST="$HOME/.local/share/man/man1"
fi

# Create destination directory
mkdir -p "$MAN_DEST"

# Copy man pages
echo "Installing man pages to: $MAN_DEST"
cp "$MAN_SOURCE/41.1" "$MAN_DEST/"
cp "$MAN_SOURCE/41swara.1" "$MAN_DEST/"

# Update man database
echo "Updating man database..."
if command -v mandb &> /dev/null; then
    if [ "$EUID" -eq 0 ]; then
        mandb -q
    else
        mandb -q -u "$HOME/.local/share/man" 2>/dev/null || true
    fi
fi

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  man 41"
echo "  man 41swara"
echo ""

# If installed to user directory, remind about MANPATH
if [ "$EUID" -ne 0 ]; then
    echo "Note: You may need to add this to your shell profile:"
    echo "  export MANPATH=\"\$HOME/.local/share/man:\$MANPATH\""
    echo ""
fi
