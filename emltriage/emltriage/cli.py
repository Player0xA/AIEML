"""CLI for emltriage."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from emltriage.core.manifest import create_manifest
from emltriage.core.parser import create_iocs_json, parse_eml_file
from emltriage.core.redact import redact_artifacts
from emltriage.core.models import AnalysisMode, IOCsExtracted
from emltriage.core.io import save_artifacts, save_iocs, save_auth_results
from emltriage.reporting.markdown import generate_markdown_report
from emltriage.utils.logging import configure_logging, get_logger

app = typer.Typer(
    name="emltriage",
    help="DFIR-grade email analysis tool",
    no_args_is_help=True,
)
console = Console()
logger = get_logger(__name__)


@app.command()
def analyze(
    eml_file: Path = typer.Argument(..., help="Path to .eml file"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    mode: AnalysisMode = typer.Option(
        AnalysisMode.TRIAGE,
        "--mode",
        "-m",
        help="Analysis mode",
    ),
    offline: bool = typer.Option(
        True,
        "--offline/--online",
        help="Run in offline mode (default: True)",
    ),
    redact: bool = typer.Option(
        False,
        "--redact",
        "-r",
        help="Redact PII",
    ),
    dns: bool = typer.Option(
        False,
        "--dns",
        help="Perform DNS lookups (requires online mode)",
    ),
    no_ioc_filter: bool = typer.Option(
        False,
        "--no-ioc-filter",
        help="Disable infrastructure IOC filtering (keep all IOCs)",
    ),
    brands_file: Optional[Path] = typer.Option(
        None,
        "--brands-file",
        "-b",
        help="Custom brand configuration file (YAML) for impersonation detection",
    ),
    exclude_brands: Optional[str] = typer.Option(
        None,
        "--exclude-brands",
        "-e",
        help="Comma-separated list of brand names to exclude from impersonation detection",
    ),
    impersonation_algorithm: str = typer.Option(
        "weighted",
        "--impersonation-algo",
        help="Impersonation scoring algorithm: simple, weighted, threshold",
    ),
    skip_impersonation: bool = typer.Option(
        False,
        "--skip-impersonation",
        help="Skip brand/domain impersonation detection",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
) -> None:
    """Analyze a single EML file."""
    # Configure logging
    configure_logging(level="DEBUG" if verbose else "INFO")
    
    # Validate inputs
    if not eml_file.exists():
        console.print(f"[red]Error: File not found: {eml_file}[/red]")
        raise typer.Exit(1)
    
    if not eml_file.suffix.lower() == '.eml':
        console.print(f"[yellow]Warning: File does not have .eml extension: {eml_file}[/yellow]")
    
    # Create output directory
    output.mkdir(parents=True, exist_ok=True)
    
    # Parse email
    console.print(f"[cyan]Analyzing: {eml_file}[/cyan]")
    
    # Parse excluded brands
    excluded_brands_list = None
    if exclude_brands:
        excluded_brands_list = [b.strip() for b in exclude_brands.split(',')]
    
    artifacts = parse_eml_file(
        file_path=eml_file,
        output_dir=output,
        mode=mode,
        offline=offline,
        redact=redact,
        perform_dns_lookup=dns and not offline,
        brand_config_path=brands_file,
        impersonation_algorithm=impersonation_algorithm,
        excluded_brands=excluded_brands_list,
        skip_impersonation=skip_impersonation,
    )
    
    # Redact if requested
    if redact:
        redact_artifacts(artifacts)
    
    # Save artifacts
    save_artifacts(artifacts, output / "artifacts.json")
    
    # Save IOCs (with optional filtering)
    iocs = create_iocs_json(artifacts, filter_infrastructure=not no_ioc_filter)
    save_iocs(iocs, output / "iocs.json")
    
    # Save auth results
    save_auth_results(artifacts.authentication, output / "auth_results.json")
    
    # Generate report
    report_md = generate_markdown_report(artifacts)
    (output / "report.md").write_text(report_md, encoding="utf-8")
    
    # Create manifest
    create_manifest(
        run_id=artifacts.metadata.run_id,
        input_file=eml_file,
        output_dir=output,
        parameters={
            "mode": mode.value,
            "offline": offline,
            "redact": redact,
            "dns": dns,
        },
    )
    
    # Display summary
    display_summary(artifacts, iocs, output)
    
    console.print(f"\n[green]Analysis complete. Output saved to: {output}[/green]")


def display_summary(artifacts, iocs: IOCsExtracted, output_dir: Path) -> None:
    """Display analysis summary."""
    # Risk score
    risk_color = {
        "low": "green",
        "medium": "yellow",
        "high": "orange",
        "critical": "red",
    }.get(artifacts.risk.severity.value, "white")
    
    # Count actual IOCs (excluding infrastructure)
    actual_ioc_count = (
        len(iocs.domains) + len(iocs.ips) + len(iocs.emails) + 
        len(iocs.urls) + len(iocs.hashes) + len(iocs.filenames)
    )
    infra_count = len(iocs.infrastructure)
    total_count = actual_ioc_count + infra_count
    
    console.print(Panel(
        f"Risk Score: [{risk_color}]{artifacts.risk.score}/100 ({artifacts.risk.severity.value.upper()})[/{risk_color}]\n"
        f"Run ID: {artifacts.metadata.run_id}",
        title="Analysis Summary",
        border_style=risk_color,
    ))
    
    # Stats table
    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Headers", str(len(artifacts.headers)))
    table.add_row("Bodies", str(len(artifacts.bodies)))
    table.add_row("Attachments", str(len(artifacts.attachments)))
    table.add_row("URLs", str(len(artifacts.urls)))
    if infra_count > 0:
        table.add_row("IOCs (Filtered)", f"{actual_ioc_count} (filtered {infra_count} infrastructure)")
    else:
        table.add_row("IOCs", str(len(artifacts.iocs)))
    table.add_row("Routing Hops", str(len(artifacts.routing)))
    
    # Add impersonation findings count
    impersonation_count = len(artifacts.impersonation)
    if impersonation_count > 0:
        high_conf = sum(1 for f in artifacts.impersonation if f.score >= 0.85)
        if high_conf > 0:
            table.add_row("Impersonation", f"{impersonation_count} findings ({high_conf} high confidence)", style="red")
        else:
            table.add_row("Impersonation", f"{impersonation_count} findings")
    
    console.print(table)
    
    # Risk reasons
    if artifacts.risk.reasons:
        console.print("\n[yellow]Risk Factors:[/yellow]")
        for reason in artifacts.risk.reasons:
            console.print(f"  • {reason.description} (weight: {reason.weight})")
    
    # Impersonation findings
    if artifacts.impersonation:
        console.print("\n[red]Impersonation Findings:[/red]")
        for finding in artifacts.impersonation[:5]:  # Show top 5
            conf_color = "red" if finding.score >= 0.85 else "orange" if finding.score >= 0.75 else "yellow"
            console.print(f"  • [{conf_color}]⚠ {finding.brand_candidate}[/{conf_color}] in '{finding.detected_domain}'")
            console.print(f"    Technique: {finding.technique.value} | Score: {finding.score:.2f}")
            console.print(f"    {finding.explanation}")
        if len(artifacts.impersonation) > 5:
            console.print(f"  ... and {len(artifacts.impersonation) - 5} more findings")


@app.command()
def batch(
    input_path: Path = typer.Argument(..., help="Directory or glob pattern"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    mode: AnalysisMode = typer.Option(AnalysisMode.TRIAGE, "--mode", "-m"),
    offline: bool = typer.Option(True, "--offline/--online"),
    redact: bool = typer.Option(False, "--redact", "-r"),
    jsonl: bool = typer.Option(False, "--jsonl", help="Output as JSONL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Batch analyze multiple EML files."""
    configure_logging(level="DEBUG" if verbose else "INFO")
    
    # Find files
    if input_path.is_dir():
        eml_files = list(input_path.glob("**/*.eml"))
    else:
        # Treat as glob pattern
        eml_files = list(Path.cwd().glob(str(input_path)))
    
    if not eml_files:
        console.print("[red]No .eml files found[/red]")
        raise typer.Exit(1)
    
    console.print(f"[cyan]Found {len(eml_files)} EML files[/cyan]")
    
    # Process each file
    results = []
    for eml_file in eml_files:
        console.print(f"Processing: {eml_file}")
        
        file_output = output / eml_file.stem
        file_output.mkdir(parents=True, exist_ok=True)
        
        try:
            artifacts = parse_eml_file(
                file_path=eml_file,
                output_dir=file_output,
                mode=mode,
                offline=offline,
                redact=redact,
            )
            
            if redact:
                redact_artifacts(artifacts)
            
            save_artifacts(artifacts, file_output / "artifacts.json")
            
            if jsonl:
                results.append({
                    "file": str(eml_file),
                    "output_dir": str(file_output),
                    "risk_score": artifacts.risk.score,
                    "risk_severity": artifacts.risk.severity.value,
                    "run_id": artifacts.metadata.run_id,
                })
        
        except Exception as e:
            console.print(f"[red]Error processing {eml_file}: {e}[/red]")
            logger.exception(f"Failed to process {eml_file}")
    
    # Write JSONL summary
    if jsonl and results:
        jsonl_path = output / "batch_results.jsonl"
        with open(jsonl_path, "w") as f:
            for result in results:
                f.write(json.dumps(result) + "\n")
        console.print(f"[green]Batch results saved to: {jsonl_path}[/green]")


@app.command()
def report(
    artifacts_file: Path = typer.Argument(..., help="Path to artifacts.json"),
    format: str = typer.Option("md", "--format", "-f", help="Output format (md, html)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Generate report from existing artifacts."""
    if not artifacts_file.exists():
        console.print(f"[red]File not found: {artifacts_file}[/red]")
        raise typer.Exit(1)
    
    # Load artifacts
    from emltriage.core.models import Artifacts
    artifacts = Artifacts.model_validate_json(artifacts_file.read_text())
    
    # Generate report
    if format == "md":
        report_content = generate_markdown_report(artifacts)
        default_output = artifacts_file.parent / "report.md"
    else:
        console.print("[red]HTML format not yet implemented[/red]")
        raise typer.Exit(1)
    
    out_file = output or default_output
    out_file.write_text(report_content, encoding="utf-8")
    console.print(f"[green]Report saved to: {out_file}[/green]")


@app.command()
def cti(
    iocs_file: Path = typer.Argument(..., help="Path to iocs.json"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file for cti.json"),
    providers: Optional[list[str]] = typer.Option(
        None,
        "--provider",
        "-p",
        help="CTI providers to use (virustotal, abuseipdb, urlhaus, local)",
    ),
    offline: bool = typer.Option(
        True,
        "--offline/--online",
        help="Run in offline mode (default: True)",
    ),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache",
        "-c",
        help="Path to cache database",
    ),
    watchlist_dir: Optional[list[str]] = typer.Option(
        None,
        "--watchlist",
        "-w",
        help="Directory containing local watchlist files",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Enrich IOCs with CTI data."""
    configure_logging(level="DEBUG" if verbose else "INFO")
    
    # Validate input
    if not iocs_file.exists():
        console.print(f"[red]Error: File not found: {iocs_file}[/red]")
        raise typer.Exit(1)
    
    # Set default output if not specified
    if output is None:
        output = iocs_file.parent / "cti.json"
    
    # Build provider list
    from emltriage.cti import CTIEngine, CTIProviderType, LocalIntelConfig
    
    provider_types = None
    if providers:
        provider_types = []
        for p in providers:
            try:
                provider_types.append(CTIProviderType(p.lower()))
            except ValueError:
                console.print(f"[yellow]Warning: Unknown provider '{p}'[/yellow]")
    
    # Build local intel config
    intel_config = None
    if watchlist_dir:
        intel_config = LocalIntelConfig(
            enabled=True,
            watchlist_dirs=list(watchlist_dir),
            auto_reload=True,
        )
    
    # Initialize engine
    engine = CTIEngine(
        cache_path=cache_path,
        offline=offline,
        providers=provider_types,
        local_intel_config=intel_config,
    )
    
    # Perform enrichment
    console.print(f"[cyan]Enriching IOCs from: {iocs_file}[/cyan]")
    
    enrichment = engine.enrich_from_file(iocs_file)
    
    # Save results
    import json
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(enrichment.model_dump(), indent=2, default=str),
        encoding="utf-8"
    )
    
    # Display summary
    summary = enrichment.summary
    console.print(f"\n[green]Enrichment complete:[/green]")
    console.print(f"  Total lookups: {summary.total_lookups}")
    console.print(f"  Cache hits: {summary.cache_hits}")
    console.print(f"  Malicious IOCs: {summary.malicious_count}")
    console.print(f"  Suspicious IOCs: {summary.suspicious_count}")
    console.print(f"  Errors: {summary.error_count}")
    console.print(f"\n[green]Results saved to: {output}[/green]")


@app.command()
def ai(
    artifacts_file: Path = typer.Argument(..., help="Path to artifacts.json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for ai_report.json and ai_report.md"),
    provider: str = typer.Option("ollama", "--provider", "-p", help="AI provider (ollama, openai, anthropic)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name (provider-specific)"),
    temperature: float = typer.Option(0.1, "--temperature", "-t", help="Sampling temperature (0.0-1.0)"),
    auth_results: Optional[Path] = typer.Option(None, "--auth", "-a", help="Path to auth_results.json"),
    cti_file: Optional[Path] = typer.Option(None, "--cti", "-c", help="Path to cti.json"),
    max_retries: int = typer.Option(2, "--retries", "-r", help="Max validation retries"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Generate AI narrative analysis of email artifacts."""
    configure_logging(level="DEBUG" if verbose else "INFO")
    
    # Validate input
    if not artifacts_file.exists():
        console.print(f"[red]Error: File not found: {artifacts_file}[/red]")
        raise typer.Exit(1)
    
    # Set default output directory
    if output is None:
        output = artifacts_file.parent
    output.mkdir(parents=True, exist_ok=True)
    
    # Initialize AI engine
    from emltriage.ai import AIEngine, AIProviderType
    
    try:
        provider_type = AIProviderType(provider.lower())
    except ValueError:
        console.print(f"[red]Error: Unknown provider '{provider}'[/red]")
        raise typer.Exit(1)
    
    try:
        engine = AIEngine(
            provider_type=provider_type,
            model=model,
            temperature=temperature,
            max_retries=max_retries,
        )
    except RuntimeError as e:
        console.print(f"[red]Error: Failed to initialize AI provider: {e}[/red]")
        raise typer.Exit(1)
    
    # Generate analysis
    console.print(f"[cyan]Generating AI analysis with {provider}:{model or 'default'}...[/cyan]")
    console.print("[dim]This may take a few minutes...[/dim]")
    
    try:
        report = engine.analyze(
            artifacts_file=artifacts_file,
            auth_results_file=auth_results,
            cti_file=cti_file,
        )
    except Exception as e:
        console.print(f"[red]Error during AI analysis: {e}[/red]")
        logger.exception("AI analysis failed")
        raise typer.Exit(1)
    
    # Save JSON report
    import json
    json_output = output / "ai_report.json"
    json_output.write_text(
        json.dumps(report.model_dump(), indent=2, default=str),
        encoding="utf-8"
    )
    
    # Generate and save Markdown report
    md_output = output / "ai_report.md"
    md_content = engine.generate_markdown(report)
    md_output.write_text(md_content, encoding="utf-8")
    
    # Display summary
    ed = report.metadata.evidence_discipline
    if ed.validation_passed:
        console.print(f"\n[green]✅ AI analysis complete and validated[/green]")
    else:
        console.print(f"\n[yellow]⚠️  AI analysis complete with validation warnings[/yellow]")
    
    console.print(f"\n[white]Results:[/white]")
    console.print(f"  Observations: {len(report.observations)}")
    console.print(f"  Inferences: {len(report.inferences)}")
    console.print(f"  Recommended Actions: {len(report.recommended_actions)}")
    console.print(f"  Evidence Citations: {len(set().union(*[o.evidence_refs for o in report.observations]))}")
    
    console.print(f"\n[green]JSON report: {json_output}[/green]")
    console.print(f"[green]Markdown report: {md_output}[/green]")


@app.command()
def version() -> None:
    """Show version information."""
    from emltriage import __version__
    console.print(f"emltriage version {__version__}")


if __name__ == "__main__":
    app()
