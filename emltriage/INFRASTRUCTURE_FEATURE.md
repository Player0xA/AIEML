# F2 Infrastructure Enrichment - Implementation Summary

## Overview
Successfully implemented **F2** from OSINT Blueprint: Infrastructure Enrichment with ASN, GeoIP, Domain Age, and Hosting Detection.

## What Was Built

### Module Structure
```
emltriage/infra/
├── __init__.py          # Public API exports
├── models.py            # Pydantic models (10 classes, ~400 lines)
├── engine.py            # Main enrichment engine (~400 lines)
├── asn.py               # ASN lookup providers (~300 lines)
├── rdap.py              # RDAP/WHOIS clients (~400 lines)
├── geo.py               # Geolocation providers (~200 lines)
└── hosting.py           # Hosting detection heuristics (~400 lines)
```

**Total:** ~2,100 lines of infrastructure enrichment code

### 1. Data Models (models.py)

**Core Models:**
- `InfrastructureEntry` - Complete infrastructure data for domain/IP
- `InfrastructureSummary` - Aggregated analysis results
- `ASNLInfo` - ASN, organization, country, registry
- `GeoInfo` - Geolocation with confidence scoring
- `DomainInfo` - Registration dates, registrar, age classification

**Enums:**
- `InfrastructureType` - domain, ip, ipv4, ipv6, asn
- `HostingType` - enterprise, vps, shared, bulletproof, cdn, residential, unknown
- `AgeClassification` - new (<30d), recent (30-90d), established (90d-2y), old (>2y), unknown
- `InfrastructureProviderType` - local, team_cymru, bgpview, rdap, whois, ip_api, ipinfo

**Configuration:**
- `InfrastructureConfig` - Offline mode, providers, caching, API keys

### 2. ASN Lookup (asn.py)

**Team Cymru Provider (Primary)**
- DNS-based lookups (v4.whois.cymru.com)
- Free, fast, reliable
- Supports IPv4 and IPv6
- TXT record parsing
- No API key required

**BGPView Provider (Fallback)**
- REST API (api.bgpview.io)
- Free tier: 1000 requests/day
- Rich ASN details
- Automatic retry logic

**Usage:**
```python
from emltriage.infra import ASNLookup

lookup = ASNLookup()
info = lookup.lookup("8.8.8.8")
# info.asn = 15169
# info.org = "GOOGLE"
# info.country = "US"
```

### 3. Domain Registration (rdap.py)

**RDAP Client (Primary)**
- Modern WHOIS replacement
- Structured JSON responses
- IANA bootstrap for TLD servers
- Automatic server discovery
- Supports 100+ TLDs

**WHOIS Fallback**
- Traditional WHOIS client
- Text parsing with regex
- Universal TLD support
- Works when RDAP unavailable

**Features:**
- Creation/expiration dates
- Registrar identification
- Name server extraction
- Status codes
- Automatic age calculation
- Age classification (NEW, RECENT, ESTABLISHED, OLD)

**Usage:**
```python
from emltriage.infra import DomainLookup

lookup = DomainLookup()
info = lookup.lookup("example.com")
# info.creation_date
# info.age_days = 365
# info.age_classification = AgeClassification.ESTABLISHED
```

### 4. Geolocation (geo.py)

**ip-api.com Provider (Primary)**
- Free, no API key
- 45 requests/minute (non-commercial)
- Country, region, city
- Lat/lon coordinates
- ISP identification
- Proxy/mobile detection

**ipinfo.io Provider (Fallback)**
- Free tier: 50,000 requests/month
- Optional paid token
- High accuracy
- Timezone data

**Usage:**
```python
from emltriage.infra import GeoLookup

lookup = GeoLookup()
info = lookup.lookup("8.8.8.8")
# info.country = "US"
# info.city = "Mountain View"
# info.isp = "Google LLC"
# info.confidence = 0.8
```

### 5. Hosting Detection (hosting.py)

**HostingDetector Class**
- Identifies VPS, CDN, bulletproof, residential, enterprise hosting
- Multi-factor classification with confidence scores
- Suspicious hosting detection

**Detection Methods:**
- **ASN-based:** Known VPS ASNs (DigitalOcean, Linode, Vultr, AWS, GCP, Azure, etc.)
- **Org name keywords:** "cloud", "hosting", "vps", "server"
- **Bulletproof indicators:** Known bulletproof ASNs, "bulletproof", "abuse ignored"
- **CDN detection:** Cloudflare, Fastly, Akamai ASNs
- **Residential ISPs:** Cable, DSL, mobile carriers

**Known ASNs Database:**
- 50+ VPS/Cloud ASNs
- 10+ CDN ASNs
- 20+ Enterprise ASNs
- 6+ Bulletproof ASNs (watchlist)

**Classification Confidence:**
- CDN: 0.95 (very reliable)
- Bulletproof: 0.90 (known bad actors)
- VPS: 0.85 (clear indicators)
- Enterprise: 0.80
- Residential: 0.70 (can be tricky)

**Usage:**
```python
from emltriage.infra import HostingDetector, InfrastructureEntry

detector = HostingDetector()
hosting_type, confidence, reasons = detector.classify_hosting(entry)
# hosting_type = HostingType.VPS
# confidence = 0.85
# reasons = ["Known VPS ASN: DigitalOcean"]
```

### 6. Main Engine (engine.py)

**InfrastructureEngine Class**
- Orchestrates all providers
- DNS resolution
- Caching support
- Batch enrichment
- Summary generation

**Features:**
- Enrich individual domains/IPs
- Batch processing with progress
- Automatic caching (SQLite)
- Configurable offline mode
- Cost tracking (API calls)

**Batch Enrichment:**
```python
from emltriage.infra import InfrastructureEngine, InfrastructureConfig

config = InfrastructureConfig(offline_mode=False)
engine = InfrastructureEngine(config=config)

summary = engine.enrich_batch(
    domains=["example.com", "test.org"],
    ips=["8.8.8.8", "1.1.1.1"],
    run_id="analysis-001"
)

print(f"Domains: {summary.total_domains}")
print(f"New domains: {summary.new_domains}")
print(f"Bulletproof: {summary.bulletproof_count}")
print(f"Top ASNs: {summary.top_asns}")
```

## Evidence Traceability (OSINT Blueprint Compliance)

Every enrichment includes:
- **source:** Provider name (team_cymru, rdap, ip_api)
- **query_time:** ISO8601 UTC timestamp
- **raw_response:** Raw API/lookup response (for auditing)
- **confidence:** 0.0-1.0 (for geo especially)
- **cost:** API call count (0 for local/offline)

## Offline Mode Support

All providers support offline mode:
- DNS resolution: Local system resolver only
- ASN: Skipped (returns None)
- Domain: Skipped (returns None)
- Geo: Skipped (returns None)
- Caching: Works offline (reads from SQLite)

## Integration Points

**Ready for CLI Integration:**
```python
# Add to CLI arguments:
--infra-enrich          Enable infrastructure enrichment
--offline               Run in offline mode
--ipinfo-token TOKEN    ipinfo.io API token (optional)
--skip-geo              Skip geolocation (reduce API calls)
```

**Ready for Web UI:**
- Models are JSON-serializable (Pydantic)
- Can be added to `Artifacts` model
- Panel can show:
  - Domain age badges (NEW <30d)
  - ASN + organization cards
  - Hosting flags (VPS, bulletproof)
  - Geographic map
  - Top ASNs table

**Ready for F3 Graph:**
- Nodes: domains, IPs, ASNs
- Edges: resolves_to, hosted_on, shares_asn
- Evidence attached to edges

## Files Created

1. `emltriage/infra/__init__.py` - Module exports
2. `emltriage/infra/models.py` - Data models (400 lines)
3. `emltriage/infra/engine.py` - Main engine (400 lines)
4. `emltriage/infra/asn.py` - ASN providers (300 lines)
5. `emltriage/infra/rdap.py` - Domain registration (400 lines)
6. `emltriage/infra/geo.py` - Geolocation (200 lines)
7. `emltriage/infra/hosting.py` - Hosting detection (400 lines)
8. `emltriage/config/__init__.py` - F1 bug fix
9. `INFRASTRUCTURE_FEATURE.md` - This documentation

## Dependencies to Add

```
dnspython>=2.4.0  # For DNS lookups (already in requirements)
requests>=2.31.0  # For HTTP APIs (already in requirements)
```

No new dependencies needed - uses existing libraries.

## Next Steps for Full F2 Integration

1. **CLI Integration** - Add `--infra-enrich` argument
2. **Core Models** - Add `infrastructure` field to `Artifacts`
3. **Parser Integration** - Call engine during analysis
4. **Web UI Panel** - Create "Infrastructure" panel
5. **F3 Graph** - Use infrastructure data for graph construction

## Testing

```python
# Test ASN lookup
python -c "from emltriage.infra import ASNLookup; l = ASNLookup(); print(l.lookup('8.8.8.8'))"

# Test RDAP
python -c "from emltriage.infra import DomainLookup; l = DomainLookup(); print(l.lookup('google.com'))"

# Test Geo
python -c "from emltriage.infra import GeoLookup; l = GeoLookup(); print(l.lookup('8.8.8.8'))"

# Test Full Engine
python -c "
from emltriage.infra import InfrastructureEngine
engine = InfrastructureEngine()
entry = engine.enrich_domain('example.com')
print(f'ASN: {entry.asn}')
print(f'Hosting: {entry.hosting_type}')
"
```

## Status

**✅ F2 INFRASTRUCTURE MODULE COMPLETE**

- ✅ ASN lookup (Team Cymru + BGPView)
- ✅ Domain registration (RDAP + WHOIS)
- ✅ Geolocation (ip-api + ipinfo)
- ✅ Hosting detection (VPS/bulletproof/CDN)
- ✅ Domain age classification
- ✅ Main enrichment engine
- ✅ Batch processing
- ✅ Caching support
- ✅ Offline mode
- ✅ Evidence traceability
- ✅ ~2,100 lines of production code

**Ready for:**
- CLI integration
- Web UI panel
- F3 Graph construction
