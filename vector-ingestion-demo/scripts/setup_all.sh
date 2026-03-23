#!/bin/bash
# ============================================================
# Complete Setup Script for Vector Ingestion Demo
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo "🚀 Vector Ingestion Demo Setup"
echo "============================================================"
echo

# Create directories
echo "📁 Creating directories..."
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/output/snowflake"
mkdir -p "$PROJECT_DIR/output/splunk"
mkdir -p "$PROJECT_DIR/data/vector"
mkdir -p "$PROJECT_DIR/data/postgres"
echo "   ✓ Directories created"

# Check if .env exists
if [ ! -f "$PROJECT_DIR/.env" ]; then
    if [ -f "$PROJECT_DIR/env.example" ]; then
        echo "📝 Creating .env from example..."
        cp "$PROJECT_DIR/env.example" "$PROJECT_DIR/.env"
        echo "   ✓ .env created - please update with your credentials"
    fi
fi

# Install Vector if not present
if [ ! -f "$HOME/.local/bin/vector" ]; then
    echo "📦 Installing Vector..."
    bash "$SCRIPT_DIR/install_vector.sh"
else
    echo "✓ Vector already installed"
fi

# Check PostgreSQL
if command -v pg_ctl &> /dev/null; then
    echo "✓ PostgreSQL available via pixi"
else
    echo "⚠️  PostgreSQL not found. Run: pixi install"
fi

echo
echo "============================================================"
echo "✅ Setup Complete!"
echo "============================================================"
echo
echo "Next steps:"
echo
echo "1. Initialize PostgreSQL (first time only):"
echo "   pixi run pg-init"
echo
echo "2. Start PostgreSQL:"
echo "   pixi run pg-start"
echo
echo "3. Generate sample logs:"
echo "   pixi run generate-all"
echo
echo "4. Run attack simulation (with PostgreSQL running):"
echo "   pixi run pg-attacks"
echo
echo "5. Upload to Snowflake (configure .env first):"
echo "   pixi run upload-csv"
echo
echo "6. Or run Vector for continuous ingestion:"
echo "   pixi run vector-run"
echo

