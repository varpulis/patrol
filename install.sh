#!/bin/sh
# patrol installer — downloads the latest release binary
# Usage: curl -sSf https://raw.githubusercontent.com/varpulis/patrol/main/install.sh | sh

set -e

REPO="varpulis/patrol"
INSTALL_DIR="${PATROL_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  TARGET_OS="linux" ;;
    Darwin) TARGET_OS="macos" ;;
    MINGW*|MSYS*|CYGWIN*) TARGET_OS="windows" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64)   TARGET_ARCH="x86_64" ;;
    aarch64|arm64)   TARGET_ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if [ "$TARGET_OS" = "windows" ]; then
    BINARY="patrol-${TARGET_OS}-${TARGET_ARCH}.exe"
else
    BINARY="patrol-${TARGET_OS}-${TARGET_ARCH}"
fi

# Get latest release tag
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Could not determine latest version. Install with cargo instead:"
    echo "  cargo install patrol"
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"

echo "Installing patrol ${LATEST} (${TARGET_OS}/${TARGET_ARCH})..."
echo "Downloading ${URL}"

# Download
TMPFILE=$(mktemp)
if ! curl -sSfL "$URL" -o "$TMPFILE"; then
    echo "Download failed. Install with cargo instead:"
    echo "  cargo install patrol"
    rm -f "$TMPFILE"
    exit 1
fi

# Install
chmod +x "$TMPFILE"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMPFILE" "${INSTALL_DIR}/patrol"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMPFILE" "${INSTALL_DIR}/patrol"
fi

echo "patrol ${LATEST} installed to ${INSTALL_DIR}/patrol"
echo ""
echo "Try it:"
echo "  patrol --help"
echo "  echo '{\"event_type\":\"A\"}' | patrol 'A'"
