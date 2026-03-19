import os
import logging
from typing import Any
try:
    from docx import Document
    from docx.shared import Inches, Pt
    from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
except ImportError:
    # Ensure graceful handling if python-docx isn't installed
    Document = None

from .models import (
    RenderModel, HeadingBlock, ParagraphBlock, 
    TableBlock, ListBlock, ImageBlock, PageBreakBlock
)

logger = logging.getLogger(__name__)

def render_docx(render_model: RenderModel, output_path: str) -> str:
    """Renders a strict RenderModel into a real DOCX file."""
    if Document is None:
        raise ImportError("python-docx is not installed. Please install it with 'pip install python-docx'")
        
    doc = Document()
    
    # Main Title
    title = render_model.document.get("title", "Reporte de Análisis de Correo")
    doc.add_heading(title, 0)
    
    # Process explicitly defined sections and blocks
    for section in render_model.sections:
        # Avoid empty sections
        if not section.blocks:
            continue
            
        # Section Title
        doc.add_heading(section.title, level=1)
        
        for block in section.blocks:
            # Rehydrate based on exact Pydantic types ensuring strict logic
            if isinstance(block, HeadingBlock) or block.type == "heading":
                doc.add_heading(block.text, level=block.level)
                
            elif isinstance(block, ParagraphBlock) or block.type == "paragraph":
                doc.add_paragraph(block.text)
                
            elif isinstance(block, TableBlock) or block.type == "table":
                _render_table(doc, block)
                
            elif isinstance(block, ListBlock) or block.type == "list":
                style = 'List Bullet' if block.style == 'bullet' else 'List Number'
                for item in block.items:
                    doc.add_paragraph(str(item), style=style)
                    
            elif isinstance(block, ImageBlock) or block.type == "image":
                if os.path.exists(block.path):
                    width = Inches(block.width) if block.width else None
                    try:
                        doc.add_picture(block.path, width=width)
                        # Center align image
                        last_paragraph = doc.paragraphs[-1]
                        last_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
                    except Exception as e:
                        logger.error(f"Failed to load image at {block.path}: {e}")
                        p = doc.add_paragraph(f"[Error loading image: {block.path}]")
                        # (We skip font.color logic to avoid complexity missing the package in some envs)
                else:
                    doc.add_paragraph(f"[Image not found: {block.path}]")
                    
                if block.caption:
                    caption = doc.add_paragraph(block.caption, style='Caption')
                    caption.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
                    
            elif isinstance(block, PageBreakBlock) or block.type == "page_break":
                doc.add_page_break()
                
    doc.save(output_path)
    return output_path

def _render_table(doc: Any, block: TableBlock):
    """Renders horizontal or vertical tables enforcing the contract."""
    if not block.rows:
        return
        
    if block.layout == "horizontal":
        if not block.columns:
            raise ValueError("Horizontal layout requires columns")
            
        table = doc.add_table(rows=1, cols=len(block.columns))
        table.style = 'Table Grid'
        
        # Header row
        hdr_cells = table.rows[0].cells
        for idx, col_name in enumerate(block.columns):
            hdr_cells[idx].text = str(col_name)
            
        # Data rows
        for row_data in block.rows:
            row_cells = table.add_row().cells
            if isinstance(row_data, dict):
                for idx, col_name in enumerate(block.columns):
                    row_cells[idx].text = str(row_data.get(col_name, ""))
            elif isinstance(row_data, list):
                for idx, cell_val in enumerate(row_data):
                    if idx < len(row_cells):
                        row_cells[idx].text = str(cell_val)
                        
    elif block.layout == "vertical":
        # Two-column key-value table
        table = doc.add_table(rows=0, cols=2)
        table.style = 'Table Grid'
        
        for row_item in block.rows:
            if isinstance(row_item, dict):
                for k, v in row_item.items():
                    row_cells = table.add_row().cells
                    row_cells[0].text = str(k)
                    row_cells[1].text = str(v)
            elif isinstance(row_item, list) and len(row_item) >= 2:
                row_cells = table.add_row().cells
                row_cells[0].text = str(row_item[0])
                row_cells[1].text = str(row_item[1])

    if block.caption:
        caption = doc.add_paragraph(block.caption, style='Caption')
        caption.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
