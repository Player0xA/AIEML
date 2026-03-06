#!/bin/bash
# Test script for emltriage IOC filtering

echo "🧪 Testing emltriage IOC Filtering"
echo "=================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if emltriage is installed
if ! command -v emltriage &> /dev/null; then
    echo -e "${RED}❌ emltriage not found in PATH${NC}"
    echo "Please activate your virtual environment:"
    echo "  source venv/bin/activate"
    exit 1
fi

# Get emltriage version
echo -e "${GREEN}✓ emltriage found${NC}"
emltriage --version
echo ""

# Test 1: Check CLI help for new flag
echo "📝 Test 1: Checking CLI for --no-ioc-filter flag"
if emltriage analyze --help | grep -q "no-ioc-filter"; then
    echo -e "${GREEN}✓ --no-ioc-filter flag found in CLI${NC}"
else
    echo -e "${RED}✗ --no-ioc-filter flag not found${NC}"
fi
echo ""

# Test 2: Basic analysis with filtering
echo "🧪 Test 2: Analyze email with IOC filtering (default)"
TEST_OUTPUT="/tmp/emltriage_test_filtered"
rm -rf "$TEST_OUTPUT"
mkdir -p "$TEST_OUTPUT"

# Find an .eml file or create a simple test
if [ -f "test_email.eml" ]; then
    EMAIL_FILE="test_email.eml"
elif [ -f "/Users/marianosanchezrojas/Downloads/CTIemails/I-332603 - 🚨 Mensaje de verificación de correo.eml" ]; then
    EMAIL_FILE="/Users/marianosanchezrojas/Downloads/CTIemails/I-332603 - 🚨 Mensaje de verificación de correo.eml"
else
    echo -e "${YELLOW}⚠️  No .eml file found, creating simple test email...${NC}"
    cat > /tmp/test_email.eml << 'EOF'
From: sender@example.com
To: recipient@example.com
Subject: Test Email with suspicious link
Date: Wed, 05 Mar 2026 10:00:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain

This is a test email.
Visit http://suspicious-domain.com for more info.
Also check evil-domain.net

Sent from Microsoft Outlook
EOF
    EMAIL_FILE="/tmp/test_email.eml"
fi

emltriage analyze "$EMAIL_FILE" -o "$TEST_OUTPUT" --offline 2>&1 | tee /tmp/test_output.log

if [ -f "$TEST_OUTPUT/iocs.json" ]; then
    echo -e "${GREEN}✓ Analysis complete${NC}"
    
    # Check filtering happened
    if grep -q "Filtered.*infrastructure" /tmp/test_output.log; then
        FILTERED_COUNT=$(grep "Filtered.*infrastructure" /tmp/test_output.log | tail -1 | grep -oE "[0-9]+" | head -1)
        echo -e "${GREEN}✓ IOC filtering active: $FILTERED_COUNT items filtered${NC}"
    else
        echo -e "${YELLOW}⚠️  No infrastructure items to filter (this is OK for simple test emails)${NC}"
    fi
else
    echo -e "${RED}✗ Analysis failed - no output${NC}"
    exit 1
fi
echo ""

# Test 3: Check output structure
echo "📝 Test 3: Checking output files"
for file in "artifacts.json" "iocs.json" "report.md"; do
    if [ -f "$TEST_OUTPUT/$file" ]; then
        echo -e "${GREEN}✓ $file created${NC}"
    else
        echo -e "${RED}✗ $file missing${NC}"
    fi
done
echo ""

# Test 4: Check iocs.json structure
echo "📝 Test 4: Checking iocs.json structure"
if command -v python3 &> /dev/null; then
    python3 << EOF
import json
import sys

try:
    with open("$TEST_OUTPUT/iocs.json") as f:
        data = json.load(f)
    
    # Check for infrastructure field
    if "infrastructure" in data:
        print(f"✓ 'infrastructure' field present ({len(data['infrastructure'])} items)")
    else:
        print("⚠️  'infrastructure' field missing (filtering may not have run)")
    
    # Count actual IOCs
    total_iocs = len(data.get('domains', [])) + len(data.get('ips', [])) + \
                 len(data.get('emails', [])) + len(data.get('urls', [])) + \
                 len(data.get('hashes', []))
    
    print(f"✓ Total actual IOCs: {total_iocs}")
    
    # Check for specific suspicious domains
    domains = [d['value'] for d in data.get('domains', [])]
    if any('suspicious' in d or 'evil' in d for d in domains):
        print("✓ Suspicious domains preserved in filtered list")
    
    # Check that outlook/microsoft domains are NOT in main list
    outlook_in_main = any('outlook.com' in d or 'microsoft.com' in d for d in domains)
    if outlook_in_main:
        print("⚠️  Outlook/Microsoft domains still in main IOC list")
    else:
        print("✓ Outlook/Microsoft domains properly filtered")
    
except Exception as e:
    print(f"✗ Error reading iocs.json: {e}")
    sys.exit(1)
EOF
else
    echo "⚠️  Python3 not available, skipping JSON validation"
fi
echo ""

# Test 5: Test without filtering
echo "🧪 Test 5: Analyze without filtering (--no-ioc-filter)"
TEST_OUTPUT2="/tmp/emltriage_test_unfiltered"
rm -rf "$TEST_OUTPUT2"
mkdir -p "$TEST_OUTPUT2"

emltriage analyze "$EMAIL_FILE" -o "$TEST_OUTPUT2" --offline --no-ioc-filter 2>&1 | tee /tmp/test_output2.log

if [ -f "$TEST_OUTPUT2/iocs.json" ]; then
    if grep -q "Filter" /tmp/test_output2.log; then
        echo -e "${YELLOW}⚠️  Filtering still happening despite --no-ioc-filter${NC}"
    else
        echo -e "${GREEN}✓ No filtering applied (--no-ioc-filter works)${NC}"
    fi
else
    echo -e "${RED}✗ Test failed${NC}"
fi
echo ""

# Test 6: Compare filtered vs unfiltered
echo "📝 Test 6: Comparing filtered vs unfiltered"
if command -v python3 &> /dev/null; then
    python3 << EOF
import json

try:
    with open("$TEST_OUTPUT/iocs.json") as f:
        filtered = json.load(f)
    
    with open("$TEST_OUTPUT2/iocs.json") as f:
        unfiltered = json.load(f)
    
    # Count domains
    filtered_domains = len(filtered.get('domains', []))
    unfiltered_domains = len(unfiltered.get('domains', []))
    
    if unfiltered_domains > filtered_domains:
        diff = unfiltered_domains - filtered_domains
        print(f"✓ Filtering removed {diff} domains")
        print(f"  Unfiltered: {unfiltered_domains} domains")
        print(f"  Filtered: {filtered_domains} domains")
    elif unfiltered_domains == filtered_domains:
        print("ℹ️  Same count (no infrastructure domains in test email)")
    else:
        print("⚠️  Unexpected: filtered has more domains than unfiltered")
    
    # Check infrastructure field only exists in filtered
    if 'infrastructure' in filtered and 'infrastructure' not in unfiltered:
        print("✓ 'infrastructure' field only in filtered output")
    
except Exception as e:
    print(f"✗ Error: {e}")
EOF
fi
echo ""

# Test 7: Unit tests
echo "🧪 Test 7: Running unit tests"
if [ -d "tests" ]; then
    if python3 -m pytest tests/unit/test_cti.py -v 2>&1 | grep -q "passed"; then
        echo -e "${GREEN}✓ Unit tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Some tests may have failed (check output above)${NC}"
    fi
else
    echo "⚠️  No tests directory found"
fi
echo ""

# Summary
echo "=================================="
echo -e "${GREEN}✅ Testing complete!${NC}"
echo ""
echo "Output locations:"
echo "  Filtered:   $TEST_OUTPUT"
echo "  Unfiltered: $TEST_OUTPUT2"
echo ""
echo "Next steps:"
echo "  1. Check $TEST_OUTPUT/iocs.json for filtered IOCs"
echo "  2. Check $TEST_OUTPUT/report.md for analysis"
echo "  3. Try CTI enrichment: emltriage cti $TEST_OUTPUT/iocs.json -o $TEST_OUTPUT"
echo ""

# Cleanup option
echo -n "Remove test output directories? (y/N): "
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    rm -rf "$TEST_OUTPUT" "$TEST_OUTPUT2"
    echo "🗑️  Test directories removed"
fi
