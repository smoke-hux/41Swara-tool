# 41Swara Smart Contract Scanner - Makefile
# Version 0.4.0 - Security Researcher Edition

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all build release install install-bin install-man uninstall clean test help

all: build

# Build debug version
build:
	cargo build

# Build release version (optimized)
release:
	cargo build --release

# Run tests
test:
	cargo test

# Install everything (binary + man pages)
install: install-bin install-man
	@echo ""
	@echo "Installation complete!"
	@echo "  Binary: $(BINDIR)/41"
	@echo "  Man page: $(MANDIR)/41.1"
	@echo ""
	@echo "Usage:"
	@echo "  41 --help"
	@echo "  man 41"

# Install binary only
install-bin: release
	@echo "Installing binaries to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@cp target/release/41 $(BINDIR)/
	@cp target/release/41swara $(BINDIR)/
	@chmod 755 $(BINDIR)/41
	@chmod 755 $(BINDIR)/41swara
	@echo "Binaries installed."

# Install man pages only
install-man:
	@echo "Installing man pages to $(MANDIR)..."
	@mkdir -p $(MANDIR)
	@cp man/41.1 $(MANDIR)/
	@cp man/41swara.1 $(MANDIR)/
	@chmod 644 $(MANDIR)/41.1
	@chmod 644 $(MANDIR)/41swara.1
	@if command -v mandb >/dev/null 2>&1; then \
		echo "Updating man database..."; \
		mandb -q 2>/dev/null || true; \
	fi
	@echo "Man pages installed."

# Uninstall everything
uninstall:
	@echo "Removing installed files..."
	@rm -f $(BINDIR)/41
	@rm -f $(BINDIR)/41swara
	@rm -f $(MANDIR)/41.1
	@rm -f $(MANDIR)/41swara.1
	@if command -v mandb >/dev/null 2>&1; then \
		mandb -q 2>/dev/null || true; \
	fi
	@echo "Uninstall complete."

# Clean build artifacts
clean:
	cargo clean

# User-local installation (no sudo required)
install-user:
	@$(MAKE) install PREFIX=$(HOME)/.local MANDIR=$(HOME)/.local/share/man/man1
	@echo ""
	@echo "Make sure these are in your PATH and MANPATH:"
	@echo "  export PATH=\"\$$HOME/.local/bin:\$$PATH\""
	@echo "  export MANPATH=\"\$$HOME/.local/share/man:\$$MANPATH\""

# Show help
help:
	@echo "41Swara Smart Contract Scanner - Build & Install"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build debug version (default)"
	@echo "  build         Build debug version"
	@echo "  release       Build optimized release version"
	@echo "  test          Run test suite"
	@echo "  install       Install binary and man pages (requires sudo)"
	@echo "  install-user  Install to ~/.local (no sudo required)"
	@echo "  install-bin   Install binary only"
	@echo "  install-man   Install man pages only"
	@echo "  uninstall     Remove installed files"
	@echo "  clean         Remove build artifacts"
	@echo "  help          Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make release           # Build optimized binary"
	@echo "  sudo make install      # System-wide install"
	@echo "  make install-user      # User-local install (no sudo)"
	@echo ""
	@echo "After installation:"
	@echo "  41 --help              # Show scanner help"
	@echo "  man 41                 # View manual page"
