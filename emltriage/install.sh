#!/bin/bash
# Easy install script for emltriage

set -e

echo "🔧 emltriage Installer"
echo "======================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
REQUIRED_VERSION="3.11"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo "❌ Error: Python 3.11+ required (found $PYTHON_VERSION)"
    exit 1
fi

echo "✅ Python version check passed ($PYTHON_VERSION)"

# Check if we're in a git repo or need to clone
if [ ! -f "pyproject.toml" ]; then
    echo "📦 Cloning emltriage repository..."
    git clone https://github.com/dfir/emltriage.git /tmp/emltriage
    cd /tmp/emltriage
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "🐍 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip -q

# Install base package
echo "📥 Installing emltriage base package..."
pip install -e . -q

# Ask about optional features
echo ""
echo "🎯 Optional Features:"
echo "1. Basic (offline only) - Recommended for privacy"
echo "2. With AI support (requires Ollama or API keys)"
echo "3. With all online features (CTI + AI)"
echo ""
read -p "Select option (1-3) [1]: " OPTION
OPTION=${OPTION:-1}

case $OPTION in
    1)
        echo "✅ Basic installation complete!"
        ;;
    2)
        echo "🤖 Installing AI dependencies..."
        pip install ollama -q 2>/dev/null || echo "Note: Install Ollama separately from ollama.com"
        echo "✅ AI support installed!"
        echo ""
        echo "To use OpenAI: export OPENAI_API_KEY='your-key'"
        echo "To use Anthropic: export ANTHROPIC_API_KEY='your-key'"
        echo "To use Ollama: Install from https://ollama.com"
        ;;
    3)
        echo "🌐 Installing all online dependencies..."
        echo "🤖 Installing AI dependencies..."
        pip install ollama -q 2>/dev/null || true
        echo "✅ Full installation complete!"
        echo ""
        echo "Set API keys for online features:"
        echo "  export VIRUSTOTAL_API_KEY='your-key'"
        echo "  export ABUSEIPDB_API_KEY='your-key'"
        echo "  export OPENAI_API_KEY='your-key' (optional)"
        echo "  export ANTHROPIC_API_KEY='your-key' (optional)"
        ;;
    *)
        echo "✅ Basic installation complete!"
        ;;
esac

echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
echo "Quick Start:"
echo "  source venv/bin/activate"
echo "  emltriage analyze email.eml -o ./output"
echo ""
echo "Full workflow:"
echo "  1. emltriage analyze email.eml -o ./output"
echo "  2. emltriage cti ./output/iocs.json -o ./output -w ./watchlists/"
echo "  3. emltriage ai ./output/artifacts.json -o ./output"
echo ""
echo "Documentation: cat README.md"
echo "Help: emltriage --help"
