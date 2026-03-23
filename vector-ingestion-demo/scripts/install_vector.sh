#!/bin/bash
# Install Vector for log collection

set -e

VECTOR_VERSION="0.35.0"
INSTALL_DIR="${HOME}/.local/bin"

echo "🚀 Installing Vector v${VECTOR_VERSION}..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        ARCH="x86_64"
        ;;
    arm64|aarch64)
        ARCH="aarch64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    darwin)
        OS="apple-darwin"
        ;;
    linux)
        OS="unknown-linux-gnu"
        ;;
    *)
        echo "❌ Unsupported OS: $OS"
        exit 1
        ;;
esac

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and install
DOWNLOAD_URL="https://packages.timber.io/vector/${VECTOR_VERSION}/vector-${VECTOR_VERSION}-${ARCH}-${OS}.tar.gz"
TEMP_DIR=$(mktemp -d)

echo "📥 Downloading from: $DOWNLOAD_URL"
curl -sSL "$DOWNLOAD_URL" -o "${TEMP_DIR}/vector.tar.gz"

echo "📦 Extracting..."
tar -xzf "${TEMP_DIR}/vector.tar.gz" -C "${TEMP_DIR}"

echo "📁 Installing to ${INSTALL_DIR}..."
cp "${TEMP_DIR}/vector-${ARCH}-${OS}/bin/vector" "${INSTALL_DIR}/vector"
chmod +x "${INSTALL_DIR}/vector"

# Cleanup
rm -rf "${TEMP_DIR}"

# Verify installation
if command -v vector &> /dev/null; then
    echo "✅ Vector installed successfully!"
    vector --version
else
    echo "⚠️  Vector installed to ${INSTALL_DIR}/vector"
    echo "   Add to PATH: export PATH=\"\$PATH:${INSTALL_DIR}\""
    "${INSTALL_DIR}/vector" --version
fi

echo ""
echo "📝 Next steps:"
echo "   1. Copy credentials: cp config/credentials.example.toml config/credentials.toml"
echo "   2. Edit credentials: nano config/credentials.toml"
echo "   3. Generate logs: pixi run generate-attack"
echo "   4. Run Vector: pixi run vector-run"

