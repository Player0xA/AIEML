# emltriage

**DFIR-grade email analysis tool with deterministic extraction and AI narrative**

emltriage is a powerful, evidence-first email analysis tool designed for Digital Forensics and Incident Response (DFIR) workflows. It provides deterministic extraction of email artifacts, structured output with cryptographic verification, and an AI-assisted narrative layer that strictly adheres to evidence discipline.

## 🚀 Quick Start (3 Options)

### Option 1: One-Line Install (Recommended)
```bash
curl -fsSL [https://raw.githubusercontent.com/dfir/emltriage/main/install.sh](https://github.com/Player0xA/AIEML/blob/main/emltriage/install.sh) | bash
```

### Option 2: Manual Install with Makefile
```bash
git clone https://github.com/dfir/emltriage.git
cd emltriage
make install        # Basic offline installation
# OR
make install-ai     # With AI support (Ollama/OpenAI/Anthropic)
# OR
make install-dev    # Full development environment

# Start using
source venv/bin/activate
emltriage analyze suspicious.eml -o ./output
```

### Option 3: Docker (Zero Dependencies)
```bash
# Clone repo
git clone https://github.com/dfir/emltriage.git
cd emltriage

# Build and run with Ollama included
make docker-build
make docker-run

# Or manually
docker-compose up -d
```

## 📦 Installation Options

### Requirements
- Python 3.11+ (check: `python3 --version`)
- Git (for cloning)

### Method 1: Easy Install Script (Interactive)
```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/dfir/emltriage/main/install.sh | bash

# The installer will:
# 1. Check Python version
# 2. Create virtual environment
# 3. Install base dependencies
# 4. Optionally install AI support
# 5. Set up environment
```

### Method 2: pip + requirements.txt
```bash
git clone https://github.com/dfir/emltriage.git
cd emltriage

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install base dependencies
pip install -r requirements.txt

# Install with AI support (optional)
pip install -r requirements-ai.txt

# Install emltriage
pip install -e .
```

### Method 3: Docker (Isolated Environment)
```bash
# Build image
docker build -t emltriage:latest .

# Run single analysis
docker run -v $(pwd)/data:/data emltriage:latest \
  analyze /data/suspicious.eml -o /data/output

# Or use docker-compose for full stack (includes Ollama)
docker-compose up -d
```

## 🔧 Post-Installation Setup

### 1. Configure Environment (Optional)
```bash
# Copy example environment file
cp .env.example .env

# Edit .env to add API keys if needed:
# - OpenAI API key (for GPT-4)
# - Anthropic API key (for Claude)
# - VirusTotal API key (for threat intel)
# - AbuseIPDB API key (for IP reputation)
```

### 2. Set Up Ollama (for Local AI - Default)
```bash
# Install Ollama from https://ollama.com
# On macOS/Linux:
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (e.g., llama3.1)
ollama pull llama3.1

# Start Ollama server
ollama serve
```

### 3. Create Watchlists (Optional)
```bash
mkdir -p watchlists

# Create sample watchlist
cat > watchlists/my_watchlist.csv << EOF
ioc,ioc_type,list_type,description,tags,confidence
evil-domain.com,domain,blocklist,Known malicious domain,malware,1.0
suspicious-ip,ipv4,blocklist,Suspicious IP,malicious,0.9
EOF
```

## 🎯 Usage Examples

### Basic Analysis (Offline)
```bash
# Single email
emltriage analyze email.eml -o ./output

# Deep analysis with macro detection
emltriage analyze suspicious.eml -o ./output --mode deep

# Batch process directory
emltriage batch ./emails/ -o ./results --jsonl
```

### With CTI Enrichment
```bash
# Requires local watchlists or API keys
emltriage analyze email.eml -o ./output
emltriage cti ./output/iocs.json -o ./output \
  --watchlist ./watchlists/ \
  --online  # Enable online providers
```

### With AI Analysis (Default: Ollama Local)
```bash
# Ensure Ollama is running: ollama serve

# Full pipeline
emltriage analyze email.eml -o ./output
emltriage cti ./output/iocs.json -o ./output -w ./watchlists/
emltriage ai ./output/artifacts.json -o ./output \
  --cti ./output/cti.json \
  --auth ./output/auth_results.json
```

### With Cloud AI (OpenAI/Anthropic)
```bash
# Set API key
export OPENAI_API_KEY="sk-..."
# OR
export ANTHROPIC_API_KEY="sk-ant-..."

# Use cloud provider
emltriage ai ./output/artifacts.json -o ./output \
  --provider openai \
  --model gpt-4
```

## 📁 Output Structure

```
output/
├── artifacts.json          # Complete extraction artifacts
├── iocs.json              # Normalized IOCs
├── auth_results.json      # Authentication analysis
├── report.md              # Deterministic report (Phase 1)
├── manifest.json          # File hashes and metadata
├── cti.json              # CTI enrichment (Phase 2)
├── ai_report.json        # AI analysis (Phase 3)
├── ai_report.md          # AI narrative report
├── attachments/          # Carved attachments
│   ├── <id>_document.pdf
│   └── <id>_image.png
├── body_1.txt           # Decoded text body
└── body_2.html          # Decoded HTML body
```

## 🛠️ Development

```bash
# Install development dependencies
make install-dev

# Run tests
make test

# Run linter
make lint

# Format code
make format

# Type checking
make typecheck

# Clean build artifacts
make clean
```

## 🌐 API Keys (Optional)

The tool works 100% offline. Only configure these if you want cloud features:

| Provider | Environment Variable | Get Key From |
|----------|---------------------|--------------|
| OpenAI | `OPENAI_API_KEY` | https://platform.openai.com |
| Anthropic | `ANTHROPIC_API_KEY` | https://console.anthropic.com |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com |

## 🐛 Troubleshooting

### Python Version Error
```bash
# Check Python version
python3 --version  # Must be 3.11+

# If older, install newer Python or use pyenv
pyenv install 3.11
pyenv local 3.11
```

### Ollama Not Found
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Pull a model
ollama pull llama3.1
```

### Permission Errors
```bash
# Make install script executable
chmod +x install.sh

# Run with bash explicitly
bash install.sh
```

### Docker Issues
```bash
# Rebuild without cache
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Check logs
docker-compose logs -f emltriage
```

## 📚 Documentation

- [Installation Guide](./docs/installation.md) - Detailed installation options
- [Usage Guide](./docs/usage.md) - Complete command reference
- [Architecture](./docs/architecture.md) - Technical documentation
- [Phase 1 Completion](./docs/phase1_completion.md) - Core extraction
- [Phase 2 Completion](./docs/phase2_completion.md) - CTI enrichment
- [Phase 3 Completion](./docs/phase3_completion.md) - AI narrative
- [Complete Implementation](./docs/COMPLETE_IMPLEMENTATION.md) - Full summary

## 🤝 Contributing

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/emltriage.git
cd emltriage

# Set up dev environment
make install-dev

# Create branch
git checkout -b feature/my-feature

# Make changes and test
make test
make lint

# Commit and push
git add .
git commit -m "Add feature: ..."
git push origin feature/my-feature

# Create Pull Request
```

## 📄 License

MIT License - See [LICENSE](./LICENSE) file

## 🙏 Acknowledgments

- Built with [Pydantic](https://pydantic.dev/) for schema validation
- CLI powered by [Typer](https://typer.tiangolo.com/)
- Rich output via [Rich](https://rich.readthedocs.io/)
- Local AI via [Ollama](https://ollama.com)

---

**Ready to analyze suspicious emails?** Run `make install` and start with `emltriage analyze email.eml -o ./output`
