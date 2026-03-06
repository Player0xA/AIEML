# Installation Guide

This guide covers all installation methods for emltriage, from quick one-liners to Docker deployment.

## Table of Contents
- [Quick Install](#quick-install) - Get started in 30 seconds
- [Detailed Methods](#detailed-methods) - Choose your preferred approach
- [Post-Installation](#post-installation) - Essential setup steps
- [Verification](#verification) - Test your installation
- [Troubleshooting](#troubleshooting) - Common issues and fixes

## Quick Install

### Method 1: One-Line Install (Recommended for Linux/macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/dfir/emltriage/main/install.sh | bash
```

This interactive installer will:
1. Check your Python version (requires 3.11+)
2. Create a virtual environment
3. Install all dependencies
4. Optionally set up AI support

### Method 2: Git + Makefile (Recommended for Developers)
```bash
git clone https://github.com/dfir/emltriage.git
cd emltriage
make install  # or make install-ai for AI features
source venv/bin/activate
```

### Method 3: Docker (Zero System Dependencies)
```bash
git clone https://github.com/dfir/emltriage.git
cd emltriage
docker-compose up -d
```

## Detailed Methods

### Option 1: Interactive Install Script

The install script provides a guided setup with choices:

```bash
# Download installer
curl -fsSL https://raw.githubusercontent.com/dfir/emltriage/main/install.sh -o install.sh
chmod +x install.sh

# Run installer
./install.sh
```

**During installation, you'll be prompted to choose:**
- **Option 1 (Basic)**: Offline-only mode, no AI, no API keys needed
- **Option 2 (AI)**: Includes Ollama setup for local AI analysis
- **Option 3 (Full)**: All features including online CTI providers

**What the script does:**
```bash
✅ Python version check
🐍 Creating virtual environment
⬆️  Upgrading pip
📥 Installing emltriage base package
🎯 Optional Features Selection
✅ Installation Complete!
```

### Option 2: pip + requirements.txt

For those who prefer manual control:

```bash
# 1. Clone repository
git clone https://github.com/dfir/emltriage.git
cd emltriage

# 2. Create virtual environment (recommended)
python3 -m venv venv

# 3. Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 4. Upgrade pip
pip install --upgrade pip

# 5. Install base requirements (offline mode only)
pip install -r requirements.txt

# 6. Optional: Install AI support
pip install -r requirements-ai.txt

# 7. Install emltriage in editable mode
pip install -e .

# 8. Verify installation
emltriage --version
```

### Option 3: Docker Deployment

Best for isolated environments or CI/CD:

```bash
# Clone repository
git clone https://github.com/dfir/emltriage.git
cd emltriage

# Build Docker image
docker build -t emltriage:latest .

# Run analysis
docker run -v $(pwd)/data:/data emltriage:latest \
  analyze /data/suspicious.eml -o /data/output
```

**Docker Compose (Full Stack with Ollama)**

```bash
# Start all services (emltriage + Ollama for local AI)
docker-compose up -d

# The compose file includes:
# - emltriage container
# - Ollama container (for local AI)
# - Shared volumes for data/output/watchlists

# Run analysis
docker-compose exec emltriage \
  emltriage analyze /data/email.eml -o /data/output

# View logs
docker-compose logs -f emltriage

# Stop services
docker-compose down
```

### Option 4: Development Installation

For contributing or extending emltriage:

```bash
git clone https://github.com/dfir/emltriage.git
cd emltriage
make install-dev

# This installs:
# - Base package
# - AI dependencies
# - Development tools (pytest, ruff, mypy)
```

## Post-Installation

### 1. Configure Environment Variables

Copy the example environment file and customize:

```bash
cp .env.example .env

# Edit .env with your preferred editor
nano .env  # or vim .env, or code .env
```

**Minimum configuration (offline only):**
```bash
# Nothing needed! Works out of the box.
```

**For AI analysis (choose one):**
```bash
# Option A: Local AI via Ollama (default, no API key needed)
OLLAMA_BASE_URL=http://localhost:11434

# Option B: OpenAI GPT-4
OPENAI_API_KEY=sk-your-key-here

# Option C: Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**For CTI enrichment (optional):**
```bash
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### 2. Set Up Ollama (for Local AI)

Ollama is the default AI provider and runs locally on your machine:

**Installation:**
```bash
# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh

# Or download from https://ollama.com/download
```

**Pull a model:**
```bash
# Recommended: llama3.1 (8B parameters, good balance)
ollama pull llama3.1

# Alternative: mistral (faster)
ollama pull mistral

# Smaller/faster: phi3
ollama pull phi3
```

**Start Ollama server:**
```bash
# In a terminal, run:
ollama serve

# Keep this running in the background
```

**Verify Ollama:**
```bash
# Check if Ollama is responding
curl http://localhost:11434/api/tags

# List downloaded models
ollama list
```

### 3. Create Local Watchlists (Optional)

Watchlists are CSV/JSON files containing known good/bad IOCs:

```bash
# Create watchlists directory
mkdir -p watchlists

# Create sample CSV watchlist
cat > watchlists/my_threat_intel.csv << 'EOF'
ioc,ioc_type,list_type,description,tags,confidence
evil-domain.com,domain,blocklist,Known phishing domain,phishing,1.0
malware-site.xyz,domain,blocklist,Malware distribution,malware,1.0
trusted-corp.com,domain,allowlist,Corporate domain,legitimate,1.0
192.168.1.100,ipv4,blocklist,Internal test IP,private,1.0
EOF

# Create sample JSON watchlist
cat > watchlists/known_bad.json << 'EOF'
[
  {
    "ioc": "suspicious-domain.com",
    "ioc_type": "domain",
    "list_type": "blocklist",
    "description": "Suspicious domain",
    "tags": ["suspicious"],
    "confidence": 0.8
  }
]
EOF
```

**CSV Format:**
- `ioc`: The indicator value
- `ioc_type`: domain, ipv4, ipv6, email, url, hash_md5, hash_sha1, hash_sha256
- `list_type`: allowlist, blocklist, or watchlist
- `description`: Human-readable description
- `tags`: Comma-separated tags
- `confidence`: 0.0-1.0 confidence score

## Verification

### Test Installation

```bash
# Check emltriage is installed
emltriage --version

# Should output: emltriage version 0.1.0
```

### Test Basic Functionality

```bash
# Create test directory
mkdir -p test_data

# If you have a test email:
emltriage analyze test_data/sample.eml -o test_data/output

# Check output files
ls test_data/output/
# Should see: artifacts.json, iocs.json, report.md, etc.
```

### Test AI Integration (if installed)

```bash
# Ensure Ollama is running
ollama serve

# In another terminal, run AI analysis on existing artifacts
emltriage ai test_data/output/artifacts.json -o test_data/output

# Check for ai_report.json and ai_report.md
ls test_data/output/ai_report.*
```

## Troubleshooting

### Python Version Issues

**Problem:** `Error: Python 3.11+ required`

**Solution:**
```bash
# Check current version
python3 --version

# Install Python 3.11+ using pyenv
pyenv install 3.11.0
pyenv local 3.11.0

# Or use system package manager
# Ubuntu/Debian:
sudo apt-get install python3.11 python3.11-venv

# macOS:
brew install python@3.11
```

### Virtual Environment Issues

**Problem:** `ModuleNotFoundError: No module named 'emltriage'`

**Solution:**
```bash
# Ensure venv is activated
source venv/bin/activate

# Verify emltriage is installed
pip list | grep emltriage

# If not installed:
pip install -e .
```

### Ollama Connection Issues

**Problem:** `Ollama not available at http://localhost:11434`

**Solution:**
```bash
# Check if Ollama is installed
which ollama

# Start Ollama server
ollama serve &

# Verify connection
curl http://localhost:11434/api/tags

# If using Docker, ensure Ollama container is running
docker-compose ps
```

### Permission Denied

**Problem:** `Permission denied` when running install script

**Solution:**
```bash
# Make script executable
chmod +x install.sh

# Run with bash
bash install.sh

# Or run without curl pipe (safer)
curl -fsSL https://raw.githubusercontent.com/dfir/emltriage/main/install.sh -o install.sh
bash install.sh
```

### Docker Issues

**Problem:** Build fails or container won't start

**Solution:**
```bash
# Rebuild from scratch
docker-compose down
docker system prune -f  # WARNING: removes all unused containers/images
docker-compose build --no-cache
docker-compose up -d

# Check logs
docker-compose logs -f emltriage
docker-compose logs -f ollama
```

### Import Errors

**Problem:** `ImportError: cannot import name 'X' from 'emltriage...'`

**Solution:**
```bash
# Clean and reinstall
make clean
make install

# Or manually:
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Next Steps

After successful installation:

1. **Read the Usage Guide**: See [usage.md](./usage.md)
2. **Try the Examples**: Test with sample emails
3. **Set Up Watchlists**: Create your threat intel files
4. **Configure API Keys**: If using online features
5. **Read Documentation**: Architecture, Phase completions

## Uninstallation

```bash
# If using virtual environment
deactivate  # Exit venv
rm -rf venv/  # Delete venv

# If using Docker
docker-compose down -v
docker rmi emltriage:latest

# Clean all artifacts
make clean-all
```

## Getting Help

- **Documentation**: See [docs/](./) directory
- **Issues**: https://github.com/dfir/emltriage/issues
- **Discussions**: https://github.com/dfir/emltriage/discussions

---

**Installation complete?** Try your first analysis: `emltriage analyze email.eml -o ./output`
