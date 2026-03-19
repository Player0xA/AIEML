from typing import Dict, Any, List
from .models import (
    AnalysisModel, ReportDataModel, RenderModel, Section,
    HeadingBlock, ParagraphBlock, TableBlock, ListBlock, ImageBlock
)

def transform_analysis_to_report_data(analysis: AnalysisModel, ai_outputs: Dict[str, Any]) -> ReportDataModel:
    """Transforms raw AnalysisModel and AI narratives into the curated ReportDataModel (Layer 1 -> Layer 2)."""
    
    meta = analysis.metadata or {}
    
    # We build the report metadata table strictly based on the requested template
    metadata_table = {
        "TLP": meta.get("tlp", ""),
        "Línea de servicio": meta.get("linea_servicio", ""),
        "Categoría": meta.get("categoria", ""),
        "Serial": meta.get("serial", ""),
        "Fecha": meta.get("fecha", "").split(" ")[0] if meta.get("fecha") else "",
        "Ticket interno": meta.get("ticket_interno", "")
    }

    # Extract general email data
    email_data = analysis.email or {}
    general_data_table = {
        "Asunto": email_data.get("subject", ""),
        "From": email_data.get("from_header", ""),
        "To": email_data.get("to", ""),
        "Sender Domain": email_data.get("sender_domain", "")
    }

    # Extract hops
    headers_analysis = analysis.headers_analysis or {}
    hops = headers_analysis.get("hops", [])
    
    # Extract domain validation
    domain_validation = analysis.sender_domain_validation or {}
    
    # Extract artifacts
    artifacts = analysis.artifacts_analysis or {}
    
    # Extract suspicious infrastructure
    infrastructure = analysis.suspicious_infrastructure or {}

    return ReportDataModel(
        document_title="Investigación respecto a correo electrónico",
        metadata={
            "report_type": analysis.report_type,
            "case_id": analysis.case_id,
            "tlp": meta.get("tlp", ""),
            "linea_servicio": meta.get("linea_servicio", ""),
            "categoria": meta.get("categoria", ""),
            "serial": meta.get("serial", ""),
            "fecha": meta.get("fecha", "").split(" ")[0] if meta.get("fecha") else "",
            "ticket_interno": meta.get("ticket_interno", "")
        },
        metadata_table=metadata_table,
        impact_text=ai_outputs.get("posible_impacto", ""),
        summary_intro=ai_outputs.get("resumen_intro", ""),
        summary_bullets=ai_outputs.get("resumen_bullets", []),
        
        # Headers Analysis
        general_data_table=general_data_table,
        headers_intro=ai_outputs.get("headers_intro", ""),
        headers_hops=hops,
        routing_interpretation=ai_outputs.get("headers_route_interpretation", ""),
        
        # Domain Validation
        sender_domain=email_data.get("sender_domain", ""),
        domain_validation_text=ai_outputs.get("sender_domain_validation_text", ""),
        domain_evidence_image=domain_validation.get("evidence_image_path", ""),
        
        # Artifacts Analysis
        artifacts_email_body_text=ai_outputs.get("artifact_email_body_text", ""),
        email_body_image=artifacts.get("email_body_image_path", ""),
        artifacts_landing_page_text=ai_outputs.get("artifact_landing_page_text", ""),
        landing_page_image=artifacts.get("landing_page", {}).get("destination_image_path", ""),
        artifacts_exfiltration_text=ai_outputs.get("artifact_exfiltration_text", ""),
        
        # Infrastructure
        suspicious_domain=infrastructure.get("primary_domain", ""),
        infrastructure_text=ai_outputs.get("suspicious_infrastructure_text", ""),
        infrastructure_evidence_image=infrastructure.get("evidence_image_path", ""),
        
        # Conclusions & Recommendations
        conclusions_text=ai_outputs.get("conclusiones", ""),
        recommendations_list=ai_outputs.get("recomendaciones", []),
        
        # IOCs & References
        iocs_table=analysis.iocs,
        references_list=analysis.references
    )


def transform_report_data_to_render_model(data: ReportDataModel) -> RenderModel:
    """Transforms the curated ReportDataModel into a strict DOCX RenderModel (Layer 2 -> Layer 3)."""
    sections: List[Section] = []
    
    # 1. Metadatos del reporte
    if data.metadata_table:
        blocks_meta = [
            TableBlock(
                layout="horizontal",
                columns=list(data.metadata_table.keys()),
                rows=[list(data.metadata_table.values())]
            )
        ]
        sections.append(Section(id="metadatos", title="Metadatos del reporte", blocks=blocks_meta))
    
    # 2. Posible impacto
    if data.impact_text:
        sections.append(Section(
            id="posible_impacto", 
            title="Posible impacto", 
            blocks=[ParagraphBlock(text=data.impact_text)]
        ))
        
    # 3. Resumen
    blocks_summary = []
    if data.summary_intro:
        # Split intro by newlines to create multiple paragraphs if needed
        for para in data.summary_intro.split('\n\n'):
            if para.strip():
                blocks_summary.append(ParagraphBlock(text=para.strip()))
    if data.summary_bullets:
        blocks_summary.append(ListBlock(style="bullet", items=data.summary_bullets))
        
    if blocks_summary:
        sections.append(Section(id="resumen", title="Resumen", blocks=blocks_summary))
        
    # 4. Análisis
    blocks_analysis = []
    blocks_analysis.append(HeadingBlock(level=2, text="Análisis de cabeceras (headers)"))
    
    if data.headers_intro:
        blocks_analysis.append(ParagraphBlock(text=data.headers_intro))
        
    blocks_analysis.append(HeadingBlock(level=3, text="Datos generales del correo analizado"))
    
    if data.general_data_table:
        rows_vertical = [[k, v] for k, v in data.general_data_table.items() if v]
        blocks_analysis.append(TableBlock(
            layout="vertical",
            rows=rows_vertical,
            caption="Tabla 1. Datos generales del correo electrónico"
        ))
        
    if data.routing_interpretation:
        for para in data.routing_interpretation.split('\n\n'):
            if para.strip():
                blocks_analysis.append(ParagraphBlock(text=para.strip()))
                
    if data.headers_hops:
        columns = ["#", "Origen", "Destino", "Descripción"]
        rows_hops = []
        for hop in data.headers_hops:
            rows_hops.append([
                str(hop.get("hop_number", "")),
                str(hop.get("source", "")),
                str(hop.get("destination", "")),
                str(hop.get("ai_description", "")) or str(hop.get("classification", ""))
            ])
        blocks_analysis.append(TableBlock(
            layout="horizontal",
            columns=columns,
            rows=rows_hops,
            caption="Tabla 2. Trayectoria del correo"
        ))
        
    if len(blocks_analysis) > 1: # We added the HeadingBlock unconditionally
        sections.append(Section(id="analisis", title="Análisis", blocks=blocks_analysis))
        
    # 5. Validación del dominio remitente
    blocks_domain = []
    if data.domain_validation_text:
        for para in data.domain_validation_text.split('\n\n'):
            if para.strip():
                blocks_domain.append(ParagraphBlock(text=para.strip()))
    
    if data.domain_evidence_image:
        blocks_domain.append(ImageBlock(
            path=data.domain_evidence_image,
            caption="Ilustración 1. Datos generales del registro del dominio"
        ))
        
    if blocks_domain:
        domain_name = data.sender_domain
        domain_safelink = domain_name.replace(".", "[.]") if domain_name else "Desconocido"
        sections.append(Section(
            id="dominio_remitente", 
            title=f"Información sobre el dominio {domain_safelink}", 
            blocks=blocks_domain
        ))
        
    # 6. Análisis de artefactos
    blocks_artifacts = []
    if data.artifacts_email_body_text:
        for para in data.artifacts_email_body_text.split('\n\n'):
            if para.strip():
                blocks_artifacts.append(ParagraphBlock(text=para.strip()))
                
    if data.email_body_image:
        blocks_artifacts.append(ImageBlock(
            path=data.email_body_image,
            caption="Ilustración 2. Cuerpo del correo"
        ))
        
    if data.artifacts_landing_page_text:
        for para in data.artifacts_landing_page_text.split('\n\n'):
            if para.strip():
                blocks_artifacts.append(ParagraphBlock(text=para.strip()))
                
    if data.landing_page_image:
        blocks_artifacts.append(ImageBlock(
            path=data.landing_page_image,
            caption="Ilustración 3. Sitio falso de inicio de sesión"
        ))
        
    if data.artifacts_exfiltration_text:
         for para in data.artifacts_exfiltration_text.split('\n\n'):
            if para.strip():
                blocks_artifacts.append(ParagraphBlock(text=para.strip()))
                
    if blocks_artifacts:
        sections.append(Section(id="analisis_artefactos", title="Análisis de artefactos", blocks=blocks_artifacts))
        
    # 7. Información sobre el dominio sospechoso
    blocks_infra = []
    if data.infrastructure_text:
        for para in data.infrastructure_text.split('\n\n'):
            if para.strip():
                blocks_infra.append(ParagraphBlock(text=para.strip()))
                
    if data.infrastructure_evidence_image:
        blocks_infra.append(ImageBlock(
            path=data.infrastructure_evidence_image,
            caption=f"Ilustración 4. Resultado de verificación de reputación"
        ))
        
    if blocks_infra:
        sus_domain = data.suspicious_domain
        sus_domain_safelink = sus_domain.replace(".", "[.]") if sus_domain else "Desconocido"
        sections.append(Section(
            id="dominio_sospechoso",
            title=f"Información sobre el dominio {sus_domain_safelink}",
            blocks=blocks_infra
        ))
        
    # 8. Conclusiones
    if data.conclusions_text:
        blocks_conclusions = []
        for para in data.conclusions_text.split('\n\n'):
            if para.strip():
                blocks_conclusions.append(ParagraphBlock(text=para.strip()))
                
        if blocks_conclusions:
            sections.append(Section(
                id="conclusiones",
                title="Conclusiones",
                blocks=blocks_conclusions
            ))
            
    # 9. Recomendaciones
    # Special handling for recommendations, sometimes they come as a single string, sometimes list
    if data.recommendations_list:
        sections.append(Section(
            id="recomendaciones",
            title="Recomendaciones",
            blocks=[ListBlock(style="bullet", items=data.recommendations_list)]
        ))
        
    # 10. Indicadores de compromiso
    if data.iocs_table:
        columns = [
            "Indicador", "Valor", "Fecha de detección", 
            "Score VirusTotal", "Fuente", "Recomendación", "Comentario"
        ]
        rows = []
        for ioc in data.iocs_table:
            rows.append([
                str(ioc.get("indicator_type", "")).capitalize(),
                str(ioc.get("value", "")),
                str(ioc.get("detection_date", "")),
                str(ioc.get("vt_score", "")) or "-",
                str(ioc.get("source", "")) or "-",
                str(ioc.get("recommendation", "")) or "-",
                str(ioc.get("comment", "")).strip()[:100] or "-"
            ])
            
        if rows:
            sections.append(Section(
                id="iocs",
                title="Indicadores de compromiso",
                blocks=[
                    TableBlock(
                        layout="horizontal", 
                        columns=columns, 
                        rows=rows,
                        caption="Tabla 3. Indicadores de compromiso"
                    )
                ]
            ))
            
    # 11. Referencias
    if data.references_list:
        # User example shows items without types strictly formatted
        items = [ref.get("value", "Reference") if "IQSEC" in str(ref.get("value", "")) else f"{ref.get('type', '')}: {ref.get('value', '')}" for ref in data.references_list]
        items = [i for i in items if i.strip()]
        
        # Add internal IQSEC fallback if empty
        if not items:
            items = ["Fuentes internas de IQSEC"]
            
        sections.append(Section(
            id="referencias",
            title="Referencias",
            blocks=[ListBlock(style="bullet", items=items)]
        ))
        
    return RenderModel(
        document={
            "title": data.document_title,
            "metadata": data.metadata
        },
        sections=sections
    )
