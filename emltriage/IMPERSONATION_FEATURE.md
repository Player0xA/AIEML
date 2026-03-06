# F1: Domain/Brand Impersonation Detection - Implementation Summary

## Overview
Implemented **F1** from the OSINT Blueprint: Domain/Brand Impersonation Detection with full evidence traceability and configurable risk scoring.

## What Was Built

### 1. Configuration System
**File:** `emltriage/config/brands.yaml`
- Comprehensive brand list with 50+ brands across 8 categories:
  - Technology (Microsoft, Google, Apple, Amazon, etc.)
  - Financial Services (PayPal, banks, credit cards)
  - Mexican Government (INFONAVIT, FONACOT, SAT, IMSS, etc.)
  - E-Commerce & Shipping (Amazon, Mercado Libre, DHL, etc.)
  - Security & Professional Networks (Norton, LinkedIn)
  - Cryptocurrency (Coinbase, Binance, Bitso)
- Configurable scoring weights (Levenshtein: 0.35, Homoglyph: 0.30, Keyword: 0.20, Punycode: 0.15)
- Risk integration settings
- Homoglyph character mappings (Cyrillic confusables, fullwidth digits)
- Infrastructure domain exclusions

### 2. Detection Engine
**File:** `emltriage/core/analysis/impersonation.py` (~600 lines)

**Classes:**
- `BrandConfig`: Loads and manages brand configuration from YAML
- `PrecomputedBrandCache`: Pre-computes fuzzy hashes for fast lookup
- `ImpersonationDetector`: Main detection engine

**Detection Techniques:**
1. **Levenshtein Distance** (Typo-squats)
   - Detects domains with small edit distance from brand domains
   - Configurable max distance (default: 3)
   - Uses rapidfuzz for performance (fallback to pure Python)

2. **Homoglyph Detection** (Unicode confusables)
   - Detects Cyrillic characters masquerading as Latin
   - Fullwidth digits, mathematical double-struck characters
   - NFKD normalization + custom mappings

3. **Keyword Matching**
   - Detects brand names/keywords in non-brand domains
   - Checks display name vs domain mismatches
   - Brand-specific keyword lists

4. **Punycode/IDN Abuse**
   - Detects xn-- domains that decode to brand-like strings
   - Visual similarity scoring

**Scoring Algorithms:**
- `simple`: Highest individual score
- `weighted`: Weighted sum of all techniques
- `threshold`: Binary pass/fail

### 3. Data Models
**File:** `emltriage/core/models.py`

**Added:**
- `ImpersonationTechnique` enum (TYPOSQUAT, HOMOGLYPH, KEYWORD_MATCH, etc.)
- `ImpersonationAlgorithm` enum (SIMPLE, WEIGHTED, THRESHOLD)
- `ImpersonationFinding` model with full evidence traceability:
  - `brand_candidate`, `detected_domain`, `technique`
  - `score` (0.0-1.0), `severity`
  - `evidence_fields[]` (where detected)
  - `source`, `query`, `timestamp` (traceability)
  - `normalized_tokens[]` (for evidence)
  - `confidence`, `cost`, `explanation`

**Updated:**
- `Artifacts` model: Added `impersonation: list[ImpersonationFinding]`

### 4. Risk Integration
**File:** `emltriage/core/analysis/risk.py`

**Added:**
- `check_impersonation()`: Converts findings to risk reasons
- Risk weights in `constants.py`:
  - `impersonation_detected`: 30 points
  - `impersonation_high_confidence`: 40 points (score >= 0.85)
- High confidence findings trigger HIGH/CRITICAL severity

### 5. Parser Integration
**File:** `emltriage/core/parser.py`

**Added Parameters:**
- `brand_config_path`: Custom brand configuration file
- `impersonation_algorithm`: Scoring algorithm
- `excluded_brands`: List of brands to exclude
- `skip_impersonation`: Skip detection entirely

**Integration:**
- Called after IOC extraction
- Populates `artifacts.impersonation`
- Includes in risk score calculation

### 6. CLI Integration
**File:** `emltriage/cli.py`

**New Arguments:**
```bash
emltriage analyze file.eml -o ./output \
  --brands-file custom_brands.yaml \
  --exclude-brands "Microsoft,Google" \
  --impersonation-algo weighted \
  --skip-impersonation
```

**Enhanced Display:**
- Shows impersonation count in summary table
- Highlights high-confidence findings in red
- Lists top 5 findings with explanations
- Technique + score details

### 7. Dependencies
**Updated:** `requirements.txt`
- Added `pyyaml>=6.0.1` for brand config parsing
- Added `rapidfuzz>=3.0.0` for fast Levenshtein distance

## Evidence Traceability (Per OSINT Blueprint)

Every finding includes:
- **source**: `"impersonation_detector"`
- **query**: `"suspicious-domain.com vs BrandName"`
- **timestamp**: ISO8601 UTC
- **normalized_tokens**: Tokens used for matching
- **confidence**: 0.0-1.0 based on technique
- **cost**: 0 (local computation)
- **explanation**: Human-readable why flagged

## Performance Optimizations

1. **Pre-computed Cache**: Brand tokens hashed at initialization
2. **rapidfuzz**: C-optimized string distance (10-100x faster)
3. **Token Normalization**: Domains stripped of common prefixes/suffixes
4. **Early Exit**: Infrastructure domains skipped immediately
5. **Batch Processing**: All domains extracted once, then checked

## Usage Examples

### Basic Usage
```bash
emltriage analyze email.eml -o ./output
# Automatically detects Microsoft, PayPal, INFONAVIT impersonation
```

### Custom Brands
```bash
emltriage analyze email.eml -o ./output --brands-file my_brands.yaml
```

### Exclude Specific Brands
```bash
emltriage analyze email.eml -o ./output --exclude-brands "Microsoft,Google"
# Won't flag Microsoft/Google impersonation
```

### Different Algorithm
```bash
emltriage analyze email.eml -o ./output --impersonation-algo threshold
# Binary detection (any technique passing threshold = impersonation)
```

### Skip Detection
```bash
emltriage analyze email.eml -o ./output --skip-impersonation
# Faster analysis for bulk processing
```

## Testing

### Manual Test
```bash
cd /Users/marianosanchezrojas/Downloads/CTIemails/tool/emltriage
pip install pyyaml rapidfuzz
python -c "
from emltriage.core.analysis.impersonation import BrandConfig, PrecomputedBrandCache
config = BrandConfig()
print(f'Loaded {len(config.brands)} brands')
cache = PrecomputedBrandCache(config)
print(f'Cache size: {len(cache.token_hashes)} tokens')
matches = cache.fuzzy_match_brands('micr0soft', max_distance=2)
print(f'Fuzzy matches for micr0soft: {matches}')
"
```

## Files Modified/Created

**New Files:**
1. `emltriage/config/brands.yaml` - Brand configuration
2. `emltriage/core/analysis/impersonation.py` - Detection engine
3. `IMPERSONATION_FEATURE.md` - This summary

**Modified Files:**
1. `emltriage/core/models.py` - Added ImpersonationFinding model
2. `emltriage/core/parser.py` - Integrated impersonation detection
3. `emltriage/core/analysis/risk.py` - Added risk scoring
4. `emltriage/utils/constants.py` - Added impersonation risk weights
5. `emltriage/cli.py` - Added CLI arguments & display
6. `requirements.txt` - Added pyyaml, rapidfuzz

## Next Steps (Optional)

1. **Web UI Panel** - Add "Impersonation" panel with:
   - Filter controls (exclude brands at runtime)
   - Visual highlighting of suspicious domains
   - Technique explanation tooltips
   
2. **CTI Provider** - External brand intelligence:
   - PhishTank integration
   - OpenPhish feed
   - Custom threat intelligence

3. **Export Formats** - STIX/TAXII support for findings

4. **Machine Learning** - Train on labeled data for better accuracy

## Compliance

✅ **Evidence Discipline**: All findings have source, query, timestamp, raw_ref (tokens), confidence, cost
✅ **Offline-First**: All detection local, no external queries
✅ **Explainability**: Risk score decomposition + detailed explanations
✅ **Pluggable**: Configurable brands, algorithms, exclusions
✅ **Privacy**: No data leaves system

## Status

**COMPLETE** - F1 fully implemented and ready for testing

Total: ~1,200 lines of code across 7 files
- Detection engine: 600 lines
- Configuration: 300 lines (YAML)
- Integration: 300 lines
