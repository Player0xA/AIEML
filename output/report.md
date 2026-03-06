# Email Analysis Report

## Case Metadata

- **Run ID:** 541c6f07-5e5e-443d-8449-04442489448f
- **Analysis Date:** 2026-03-05T04:07:16.595567+00:00
- **Input File:** I-332595 - 🚨 Mensaje de verificación de correo.eml
- **Input SHA256:** `653ab39c964da7af3177d828ef6cdd0e31448366351e124722729ecc3c3c006d`
- **Input Size:** 212049 bytes
- **Analysis Mode:** triage
- **Offline Mode:** True
- **Redacted:** False

## Risk Assessment

**Score:** 20/100

**Severity:** LOW

### Risk Factors

- **routing_non_monotonic** (medium): Non-monotonic timestamps in routing path
  - Weight: 20
  - Evidence: routing.2.timestamp

## Headers Summary

**From:** MAGDALENA DE JESUS BARRON CONEJO <m_barronc39@seg-gto.gob.mx>
**To:** Administrativo Centro <region.centro@fonacot.gob.mx>
**Subject:** 🚨 Mensaje de verificación de correo
**Date:** Wed, 04 Mar 2026 04:30:34 +0000
**Message-ID:** <SA0PR19MB4411E817500DBC61127A5670FC7CA@SA0PR19MB4411.namprd19.prod.outlook.com>

## Routing Analysis

**Total Hops:** 6

| Hop | From | By | Date | Anomalies |
|-----|------|-----|------|------------|
| 0 | LV8PR22MB5315.namprd22.prod.outlook.com (2603:10b6:408:1ca::6) | SA0PR22MB2143.namprd22.prod.outlook.com | 2026-03-04 04:30:44 UTC | - |
| 1 | SJ0PR03CA0340.namprd03.prod.outlook.com (2603:10b6:a03:39c::15) | LV8PR22MB5315.namprd22.prod.outlook.com | 2026-03-04 04:30:38 UTC | - |
| 2 | SJ5PEPF000001F7.namprd05.prod.outlook.com (2603:10b6:a03:39c:cafe::e3) | SJ0PR03CA0340.outlook.office365.com | 2026-03-04 04:30:17 UTC | non_monotonic_timestamp |
| 3 | BL0PR03CU003.outbound.protection.outlook.com (2a01:111:f403:c101::7) | SJ5PEPF000001F7.mail.protection.outlook.com | 2026-03-04 04:30:38 UTC | - |
| 4 | SA0PR19MB4411.namprd19.prod.outlook.com (2603:10b6:806:b1::18) | SA0PR19MB4412.namprd19.prod.outlook.com | 2026-03-04 04:30:35 UTC | - |
| 5 | SA0PR19MB4411.namprd19.prod.outlook.com ([fe80::d690:8cee:d0dd:4e4c]) | SA0PR19MB4411.namprd19.prod.outlook.com | 2026-03-04 04:30:34 UTC | - |

## URLs Extracted

| URL | Source | Obfuscated | Context |
|-----|--------|-----------|----------|
| https://go.microsoft.com/fwlink/?linkid=2243825 | plain | No |  cuenta.💡



Ingresa en el enlace a continuaci... |
| https://go.microsoft.com/fwlink/?linkid=2243825 | html_href | No | <a href="https://go.microsoft.com/fwlink/?linkid=2... |

## Indicators of Compromise (IOCs)

### DOMAIN

- `lv8pr22mb5315.namprd22.prod.outlook.com` (from: header.Received)
- `sa0pr22mb2143.namprd22.prod.outlook.com` (from: header.Received)
- `sj0pr03ca0340.namprd03.prod.outlook.com` (from: header.Received)
- `sj5pepf000001f7.namprd05.prod.outlook.com` (from: header.Received)
- `sj0pr03ca0340.outlook.office365.com` (from: header.Received)
- `bl0pr03cu003.outbound.protection.outlook.com` (from: header.Received)
- `sj5pepf000001f7.mail.protection.outlook.com` (from: header.Received)
- `sa0pr19mb4411.namprd19.prod.outlook.com` (from: header.Received)
- `sa0pr19mb4412.namprd19.prod.outlook.com` (from: header.Received)
- `seg-gto.gob.mx` (from: header.From)
- `region.centro` (from: header.To)
- `fonacot.gob.mx` (from: header.To)
- `protection.outlook.com` (from: header.received-spf)
- `cvsdredtisosec.iceiy.com` (from: body_plain)
- `go.microsoft.com` (from: body_plain)
- `p.msonormal` (from: body_html)
- `li.msonormal` (from: body_html)
- `div.msonormal` (from: body_html)
- `div.wordsection` (from: body_html)
- `image001.png` (from: body_html)

*... and 4 more*

### EMAIL

- `m_barronc39@seg-gto.gob.mx` (from: header.From)
- `region.centro@fonacot.gob.mx` (from: header.To)
- `sa0pr19mb4411e817500dbc61127a5670fc7ca@sa0pr19mb4411.namprd19.prod.outlook.com` (from: header.Message-ID)

### IPV6

- `2603:10b6:408:1ca::` (from: header.Received)
- `2603:10b6:a03:39c::` (from: header.Received)
- `2603:10b6:a03:39c:cafe::` (from: header.Received)
- `2a01:111:f403:c101::` (from: header.Received)
- `2603:10b6:a0f:fc02::` (from: header.Received)
- `2603:10b6:806:b1::` (from: header.Received)
- `2603:10b6:806:ba::` (from: header.Received)
- `fe80::` (from: header.Received)

### URL

- `https://go.microsoft.com/fwlink/?linkid=2243825` (from: urls)

## Attachments

| Filename | Type | Size | SHA256 | Risky |
|----------|------|------|--------|-------|
| image001.png | unknown (python-magic not installed) | 2.6 KB | `98f062abe564d250...` | No |
| image002.png | unknown (python-magic not installed) | 102.9 KB | `0012a9262965e78c...` | No |
| image003.png | unknown (python-magic not installed) | 18.5 KB | `b1902efa0d2806e3...` | No |
| image004.png | unknown (python-magic not installed) | 3.4 KB | `f2af1e303ed2e48f...` | No |
| image005.png | unknown (python-magic not installed) | 3.9 KB | `e724599ab33d945f...` | No |

## Body Content

### Body 1: text/plain

- **Size:** 702 bytes
- **Charset:** utf-8
- **Saved to:** `../output/body_1.txt`
- **SHA256:** `057aa7de2912e45c4a1164cd40e9332a6e9f7e223f8d0b7116de00cf692c1413`

### Body 2: text/html

- **Size:** 12098 bytes
- **Charset:** utf-8
- **Saved to:** `../output/body_2.html`
- **SHA256:** `b5c9789f03403f184ae250270b5994c1852a3f38b0ef05ef688bcf07159a5f3a`

---

*This is a deterministic report generated by emltriage. All claims are backed by evidence references in `artifacts.json`.*
