"""Markdown report generation."""

from datetime import datetime
from pathlib import Path
from typing import Any

from emltriage.core.models import (
    Artifacts,
    AttachmentEntry,
    HeaderEntry,
    IOCType,
    RoutingHop,
    URLEntry,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def generate_markdown_report(artifacts: Artifacts) -> str:
    """Generate deterministic markdown report.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        Markdown report string
    """
    lines = []
    
    # Header
    lines.append("# Email Analysis Report")
    lines.append("")
    lines.append("## Case Metadata")
    lines.append("")
    lines.append(f"- **Run ID:** {artifacts.metadata.run_id}")
    lines.append(f"- **Analysis Date:** {artifacts.metadata.timestamp.isoformat()}")
    lines.append(f"- **Input File:** {artifacts.metadata.input_filename}")
    lines.append(f"- **Input SHA256:** `{artifacts.metadata.input_hash_sha256}`")
    lines.append(f"- **Input Size:** {artifacts.metadata.input_size} bytes")
    lines.append(f"- **Analysis Mode:** {artifacts.metadata.analysis_mode.value}")
    lines.append(f"- **Offline Mode:** {artifacts.metadata.offline_mode}")
    lines.append(f"- **Redacted:** {artifacts.metadata.redact_mode}")
    lines.append("")
    
    # Risk Score
    lines.append("## Risk Assessment")
    lines.append("")
    lines.append(f"**Score:** {artifacts.risk.score}/100")
    lines.append("")
    lines.append(f"**Severity:** {artifacts.risk.severity.value.upper()}")
    lines.append("")
    
    if artifacts.risk.reasons:
        lines.append("### Risk Factors")
        lines.append("")
        for reason in artifacts.risk.reasons:
            lines.append(f"- **{reason.code}** ({reason.severity.value}): {reason.description}")
            lines.append(f"  - Weight: {reason.weight}")
            lines.append(f"  - Evidence: {', '.join(reason.evidence_refs)}")
            lines.append("")
    
    # Headers Summary
    lines.append("## Headers Summary")
    lines.append("")
    
    important_headers = ['from', 'to', 'subject', 'date', 'message-id']
    for header_name in important_headers:
        for header in artifacts.headers:
            if header.name.lower() == header_name:
                value = header.decoded_value or header.raw_value
                lines.append(f"**{header.name}:** {value}")
                break
    lines.append("")
    
    # Routing
    if artifacts.routing:
        lines.append("## Routing Analysis")
        lines.append("")
        lines.append(f"**Total Hops:** {len(artifacts.routing)}")
        lines.append("")
        lines.append("| Hop | From | By | Date | Anomalies |")
        lines.append("|-----|------|-----|------|------------|")
        
        for hop in artifacts.routing:
            from_host = hop.from_host or "-"
            by_host = hop.by_host or "-"
            date_str = hop.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if hop.timestamp else hop.date_raw or "-"
            anomalies = ", ".join(hop.anomalies) if hop.anomalies else "-"
            
            lines.append(f"| {hop.hop_number} | {from_host} | {by_host} | {date_str} | {anomalies} |")
        lines.append("")
    
    # Authentication
    if artifacts.authentication.parsed_results:
        lines.append("## Authentication Results")
        lines.append("")
        
        for domain_result in artifacts.authentication.parsed_results:
            lines.append(f"### Domain: {domain_result.domain}")
            lines.append("")
            for result in domain_result.results:
                status_icon = "✅" if result.result == "pass" else "❌" if result.result in ["fail", "temperror", "permerror"] else "⚠️"
                lines.append(f"- {status_icon} **{result.mechanism.upper()}:** {result.result}")
                if result.reason:
                    lines.append(f"  - Reason: {result.reason}")
            lines.append("")
        
        if artifacts.authentication.dkim_verified is not None:
            status = "✅ Valid" if artifacts.authentication.dkim_verified else "❌ Invalid"
            lines.append(f"**DKIM Cryptographic Verification:** {status}")
            if artifacts.authentication.dkim_verify_error:
                lines.append(f"  - Error: {artifacts.authentication.dkim_verify_error}")
            lines.append("")
    
    # URLs
    if artifacts.urls:
        lines.append("## URLs Extracted")
        lines.append("")
        lines.append("| URL | Source | Obfuscated | Context |")
        lines.append("|-----|--------|-----------|----------|")
        
        for url in artifacts.urls[:50]:  # Limit to first 50
            url_display = url.deobfuscated[:80] + "..." if len(url.deobfuscated) > 80 else url.deobfuscated
            obfuscated = "Yes" if url.is_obfuscated else "No"
            context = url.context[:50] + "..." if len(url.context) > 50 else url.context
            context = context.replace("|", "\\|")  # Escape pipe
            
            lines.append(f"| {url_display} | {url.source} | {obfuscated} | {context} |")
        
        if len(artifacts.urls) > 50:
            lines.append(f"\n*... and {len(artifacts.urls) - 50} more URLs*")
        lines.append("")
    
    # IOCs
    if artifacts.iocs:
        lines.append("## Indicators of Compromise (IOCs)")
        lines.append("")
        
        # Group by type
        iocs_by_type: dict[str, list] = {}
        for ioc in artifacts.iocs:
            ioc_type = ioc.type.value
            if ioc_type not in iocs_by_type:
                iocs_by_type[ioc_type] = []
            iocs_by_type[ioc_type].append(ioc)
        
        for ioc_type, iocs in sorted(iocs_by_type.items()):
            lines.append(f"### {ioc_type.upper()}")
            lines.append("")
            for ioc in iocs[:20]:  # Limit to first 20 per type
                lines.append(f"- `{ioc.value}` (from: {ioc.source})")
            if len(iocs) > 20:
                lines.append(f"\n*... and {len(iocs) - 20} more*")
            lines.append("")
    
    # Attachments
    if artifacts.attachments:
        lines.append("## Attachments")
        lines.append("")
        lines.append("| Filename | Type | Size | SHA256 | Risky |")
        lines.append("|----------|------|------|--------|-------|")
        
        for att in artifacts.attachments:
            filename = att.filename_decoded or att.filename_raw
            filename_display = filename[:40] + "..." if len(filename) > 40 else filename
            size_kb = att.size / 1024
            risky = "⚠️ YES" if att.is_risky else "No"
            
            lines.append(f"| {filename_display} | {att.magic_type} | {size_kb:.1f} KB | `{att.hashes.sha256[:16]}...` | {risky} |")
        lines.append("")
    
    # Bodies
    if artifacts.bodies:
        lines.append("## Body Content")
        lines.append("")
        
        for i, body in enumerate(artifacts.bodies):
            lines.append(f"### Body {i+1}: {body.content_type}")
            lines.append("")
            lines.append(f"- **Size:** {body.size} bytes")
            lines.append(f"- **Charset:** {body.charset or 'N/A'}")
            if body.saved_path:
                lines.append(f"- **Saved to:** `{body.saved_path}`")
            if body.content_hash:
                lines.append(f"- **SHA256:** `{body.content_hash}`")
            lines.append("")
    
    # Evidence References Note
    lines.append("---")
    lines.append("")
    lines.append("*This is a deterministic report generated by emltriage. All claims are backed by evidence references in `artifacts.json`.*")
    lines.append("")
    
    return "\n".join(lines)
