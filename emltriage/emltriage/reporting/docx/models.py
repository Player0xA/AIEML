from typing import List, Optional, Union, Dict, Any, Literal
from pydantic import BaseModel, Field, model_validator

# ==========================================
# CAPA 1: ANALYSIS MODEL
# ==========================================

class AnalysisModel(BaseModel):
    """Raw deterministic data from technical analysis (LAYER 1)."""
    report_type: str = "email_investigation"
    case_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    email: Dict[str, Any] = Field(default_factory=dict)
    headers_analysis: Dict[str, Any] = Field(default_factory=dict)
    sender_domain_validation: Dict[str, Any] = Field(default_factory=dict)
    artifacts_analysis: Dict[str, Any] = Field(default_factory=dict)
    suspicious_infrastructure: Dict[str, Any] = Field(default_factory=dict)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    references: List[Dict[str, Any]] = Field(default_factory=list)


# ==========================================
# CAPA 2: REPORT DATA MODEL
# ==========================================

class ReportDataModel(BaseModel):
    """Curated data and AI narratives selected for the final report (LAYER 2)."""
    document_title: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    metadata_table: Dict[str, str] = Field(default_factory=dict)
    
    # Narratives and summaries
    impact_text: str = ""
    summary_intro: str = ""
    summary_bullets: List[str] = Field(default_factory=list)
    
    # Headers
    general_data_table: Dict[str, str] = Field(default_factory=dict)
    headers_intro: str = ""
    headers_hops: List[Dict[str, Any]] = Field(default_factory=list)
    routing_interpretation: str = ""
    
    # Domain
    sender_domain: str = ""
    domain_validation_text: str = ""
    domain_evidence_image: str = ""
    
    # Artifacts
    artifacts_email_body_text: str = ""
    email_body_image: str = ""
    artifacts_landing_page_text: str = ""
    landing_page_image: str = ""
    artifacts_exfiltration_text: str = ""
    
    # Infrastructure
    suspicious_domain: str = ""
    infrastructure_text: str = ""
    infrastructure_evidence_image: str = ""
    
    # Conclusions & Recommendations
    conclusions_text: str = ""
    recommendations_list: List[str] = Field(default_factory=list)
    
    # Tables
    iocs_table: List[Dict[str, Any]] = Field(default_factory=list)
    references_list: List[Dict[str, Any]] = Field(default_factory=list)


# ==========================================
# CAPA 3: RENDER MODEL
# ==========================================

class RenderBlockBase(BaseModel):
    type: str

class HeadingBlock(RenderBlockBase):
    type: Literal["heading"] = "heading"
    level: int
    text: str

class ParagraphBlock(RenderBlockBase):
    type: Literal["paragraph"] = "paragraph"
    text: str

class TableBlock(RenderBlockBase):
    type: Literal["table"] = "table"
    layout: Literal["horizontal", "vertical"]
    columns: Optional[List[str]] = None
    rows: List[Union[List[str], Dict[str, Any]]]
    caption: Optional[str] = None

    @model_validator(mode='after')
    def validate_table(self):
        if self.layout == "horizontal":
            if self.columns is None:
                raise ValueError("Horizontal tables must have 'columns'")
            if not self.rows and not isinstance(self.rows, list):
                raise ValueError("Horizontal tables must have 'rows' as a list")
            # Enforce that dict rows in horizontal tables have matching keys
            if self.rows and isinstance(self.rows[0], dict):
                for row in self.rows:
                    for col in self.columns:
                        if col not in row:
                            row[col] = "" # Auto-fill missing columns
        elif self.layout == "vertical":
            if not self.rows and not isinstance(self.rows, list):
                raise ValueError("Vertical tables must have 'rows' as a list")
        return self

class ListBlock(RenderBlockBase):
    type: Literal["list"] = "list"
    style: Literal["bullet", "numbered"]
    items: List[str]

class ImageBlock(RenderBlockBase):
    type: Literal["image"] = "image"
    path: str
    caption: Optional[str] = None
    width: Optional[float] = None

class PageBreakBlock(RenderBlockBase):
    type: Literal["page_break"] = "page_break"

RenderBlock = Union[HeadingBlock, ParagraphBlock, TableBlock, ListBlock, ImageBlock, PageBreakBlock]

class Section(BaseModel):
    id: str
    title: str
    blocks: List[RenderBlock]

class RenderModel(BaseModel):
    """The strict DOCX layout rendering definition (LAYER 3)."""
    document: Dict[str, Any] = Field(default_factory=dict)
    sections: List[Section] = Field(default_factory=list)
