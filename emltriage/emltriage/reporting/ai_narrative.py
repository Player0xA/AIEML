"""AI narrative generation for investigation reports using Ollama."""

import json
import logging
from typing import Any, Optional

from emltriage.reporting.schemas import InvestigationReport, AIOutputs
from emltriage.ai.providers.ollama import OllamaProvider

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """Eres un asistente de análisis forense de correo electrónico especializado en ciberseguridad.
Tu tarea es generar informes de investigación de correos electrónicos en español, basándote únicamente en los hechos extraídos del análisis técnico.

INSTRUCCIONES IMPORTANTES:
1. Solo usa información proporcionada en los datos de entrada
2. No inventes ni exageres hechos
3. Si no hay información disponible para un campo, déjalo vacío
4. Usa un tono profesional y técnico
5. Las conclusiones deben basarse en evidencia concreta
6. Las recomendaciones deben ser accionables y específicas

Genera el output en formato JSON con los campos solicitados."""


NARRATIVE_PROMPT_TEMPLATE = """Basándote en los siguientes datos de análisis de correo electrónico, genera los campos narrativos del informe:

=== DATOS DEL EMAIL ===
- Subject: {subject}
- From: {from_header}
- To: {to}
- Sender Domain: {sender_domain}
- Return-Path: {return_path}

=== AUTENTICACIÓN ===
- SPF: {spf_result} (dominio: {spf_domain})
- DKIM: {dkim_result} (dominio: {dkim_domain})  
- DMARC: {dmarc_result} (dominio: {dmarc_domain})

=== ENRUTAMIENTO ===
Hops:
{hops_text}

Observaciones de enrutamiento:
- Usa Microsoft 365: {uses_m365}
- Usa Exchange Online: {uses_exchange}
- Solo ruta interna: {internal_only}
- Sender autorizado en SPF: {spf_authorized}

=== VALIDACIÓN DE DOMINIO ===
- Dominio: {sender_registration_domain}
- Registrante: {registrant}
- Fecha de creación: {creation_date}
- Proveedor: {provider}
- Nombre del país: {country}
- Facts: {domain_facts}

=== ANÁLISIS DE ARTEFACTOS ===
Tema del email: {theme}
Lenguaje de presión: {pressure_lang}
Acciones solicitadas: {requested_actions}
URLs en cuerpo: {urls}
Marca suplantada: {impersonated_brand}

Landing page:
- URL: {lp_url}
- Dominio: {lp_domain}
- Marca suplantada: {lp_brand}
- Campos capturados: {lp_captured}
- Comportamiento de exfiltración: {lp_exfil}

=== INFRAESTRUCTURA SOSPECHOSA ===
- Dominio primario: {infra_domain}
- Subdominios relacionados: {subdomains}
- IPs resueltas: {ips}
- Reputación: {reputation}

=== IOCs ===
{iocs_text}

=== RIESGO ===
- Score: {risk_score}
- Severidad: {severity}

Genera el siguiente JSON exactamente con estos campos:

{{
    "posible_impacto": "描述 posible impacto en 1-2 oraciones",
    "resumen_intro": "Resumen introductorio del análisis en 2-3 oraciones",
    "resumen_bullets": ["punto 1", "punto 2", "punto 3"],
    "headers_intro": "Descripción de los resultados de autenticación (SPF/DKIM/DMARC)",
    "headers_route_interpretation": "Interpretación del enrutamiento del correo",
    "sender_domain_validation_text": "Análisis del dominio del remitente",
    "artifact_email_body_text": "Análisis del cuerpo del correo y artefactos encontrados",
    "artifact_landing_page_text": "Análisis de la página de destino si existe",
    "artifact_exfiltration_text": "Análisis de comportamiento de exfiltración si aplica",
    "suspicious_infrastructure_text": "Análisis de infraestructura sospechosa",
    "conclusiones": "Conclusiones del análisis en 2-3 oraciones",
    "recomendaciones": ["recomendación 1", "recomendación 2", "recomendación 3"]
}}

Responde SOLO con JSON válido, sin texto adicional."""


def format_hops_text(headers_analysis) -> str:
    if not headers_analysis.hops:
        return "Sin datos de enrutamiento"
    
    lines = []
    for hop in headers_analysis.hops[:5]:
        lines.append(f"- Hop {hop.hop_number}: {hop.source} -> {hop.destination} ({hop.classification})")
    return "\n".join(lines)


def format_iocs_text(iocs) -> str:
    if not iocs:
        return "Sin IOCs"
    
    lines = []
    for ioc in iocs[:10]:
        lines.append(f"- {ioc.indicator_type}: {ioc.value}")
    return "\n".join(lines)


def format_ips_text(infra) -> str:
    if not infra.resolved_ips:
        return "Sin IPs resueltas"
    
    lines = []
    for ip_data in infra.resolved_ips[:5]:
        lines.append(f"- {ip_data.ip} ({ip_data.country}, {ip_data.provider})")
    return "\n".join(lines)


class AIRegenerator:
    """AI narrative generator for investigation reports."""
    
    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.provider = OllamaProvider(model=model, base_url=base_url)
    
    def is_available(self) -> bool:
        """Check if AI provider is available."""
        return self.provider.is_available()
    
    async def generate_narrative(self, report: InvestigationReport) -> AIOutputs:
        """Generate AI narrative for the report."""
        
        if not self.is_available():
            logger.warning("Ollama not available, returning empty AI outputs")
            return AIOutputs()
        
        try:
            user_prompt = self._build_prompt(report)
            response = self.provider.generate(SYSTEM_PROMPT, user_prompt)
            
            parsed = self._parse_json_response(response)
            if parsed:
                return AIOutputs(**parsed)
            else:
                logger.warning("Failed to parse AI response as JSON")
                return AIOutputs()
                
        except Exception as e:
            logger.error(f"AI narrative generation failed: {e}")
            return AIOutputs()
    
    def _build_prompt(self, report: InvestigationReport) -> str:
        """Build the user prompt from report data."""
        
        email = report.email
        headers = report.headers_analysis
        sender_val = report.sender_domain_validation
        artifacts = report.artifacts_analysis
        infra = report.suspicious_infrastructure
        risk = report.iocs
        
        hops_text = format_hops_text(headers)
        iocs_text = format_iocs_text(report.iocs)
        ips_text = format_ips_text(infra)
        
        return NARRATIVE_PROMPT_TEMPLATE.format(
            subject=email.subject[:100],
            from_header=email.from_header[:100],
            to=email.to[:100],
            sender_domain=email.sender_domain,
            return_path=email.return_path[:100] if email.return_path else "N/A",
            spf_result=email.authentication.spf_result,
            spf_domain=email.authentication.spf_domain,
            dkim_result=email.authentication.dkim_result,
            dkim_domain=email.authentication.dkim_domain,
            dmarc_result=email.authentication.dmarc_result,
            dmarc_domain=email.authentication.dmarc_domain,
            hops_text=hops_text,
            uses_m365=str(headers.routing_observations.uses_microsoft_365),
            uses_exchange=str(headers.routing_observations.uses_exchange_online),
            internal_only=str(headers.routing_observations.internal_provider_route_only),
            spf_authorized=str(headers.routing_observations.authorized_sender_in_spf),
            sender_registration_domain=sender_val.domain,
            registrant=sender_val.registrant,
            creation_date=sender_val.creation_year,
            provider=sender_val.provider,
            country=sender_val.country,
            domain_facts=", ".join(sender_val.summary_facts[:3]) if sender_val.summary_facts else "N/A",
            theme=artifacts.email_body_indicators.theme,
            pressure_lang=", ".join(artifacts.email_body_indicators.pressure_language[:5]),
            requested_actions=", ".join(artifacts.email_body_indicators.requested_actions[:3]),
            urls=", ".join(artifacts.email_body_indicators.urls_in_body[:3]),
            impersonated_brand=artifacts.email_body_indicators.displayed_brand,
            lp_url=artifacts.landing_page.url,
            lp_domain=artifacts.landing_page.domain,
            lp_brand=artifacts.landing_page.impersonated_brand,
            lp_captured=", ".join(artifacts.landing_page.captured_fields[:3]),
            lp_exfil=", ".join(artifacts.landing_page.exfiltration_behavior[:3]),
            infra_domain=infra.primary_domain,
            subdomains=", ".join(infra.related_subdomains[:3]),
            ips=ips_text,
            reputation=f"Score: {infra.reputation.domain_score}, Detecciones: {len(infra.reputation.detections_summary)}",
            iocs_text=iocs_text,
            risk_score="N/A",
            severity="N/A"
        )
    
    def _parse_json_response(self, response: str) -> Optional[dict]:
        """Parse JSON from AI response."""
        try:
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            
            response = response.strip()
            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return None
