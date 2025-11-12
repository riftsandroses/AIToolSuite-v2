# File: methodologies/report_generator.py
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, Image
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
import os
import json
from io import BytesIO
from datetime import datetime
class DummyTOC:
    def addEntry(self, *args, **kwargs):
        pass

toc = DummyTOC()
class NumberedCanvas(canvas.Canvas):
    """Custom canvas that adds page numbers and footers"""
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []
        self.client_name = "Unknown Client"
        self.report_date = "Unknown Date"
    @property
    def pagesize(self):
        return self._pagesize
    
    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()
        
    def save(self):
        num_pages = len(self._saved_page_states)
        for (page_num, page_state) in enumerate(self._saved_page_states):
            self.__dict__.update(page_state)
            self.draw_page_number(page_num + 1, num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)
        
    def draw_page_number(self, page_num, total_pages):
        """Draw footer with client info and page numbers"""
        self.saveState()
        
        # Footer with client info and page numbers
        footer_text = f"Client: {self.client_name} | Date: {self.report_date}"
        page_text = f"Page {page_num} of {total_pages}"
        
        self.setFont("Helvetica-Oblique", 8)
        self.setFillColor(colors.grey)
        
        # Left side - client info
        self.drawString(72, 0.5 * inch, footer_text)
        # Right side - page numbers  
        self.drawRightString(self.pagesize[0] - 72, 0.5 * inch, page_text)
        self.restoreState()

def format_list_items(items, styles):
    """Helper function to format lists as bullet points"""
    if isinstance(items, list):
        formatted_items = []
        for item in items:
            formatted_items.append(f"• {item}")
        return "<br/>".join(formatted_items)
    elif isinstance(items, str):
        # If it's a string that looks like a list, try to format it
        if ',' in items:
            item_list = [item.strip() for item in items.split(',')]
            return "<br/>".join(f"• {item}" for item in item_list)
        else:
            return f"• {items}"
    return str(items)

def safe_get_attribute(obj, attr_name, default="N/A"):
    """Safely get attribute from object with fallback"""
    try:
        value = getattr(obj, attr_name, None)
        if value is None:
            return default
        if attr_name == 'last_analysis_at' and hasattr(value, 'strftime'):
            return value.strftime('%Y-%m-%d')
        return str(value)
    except (AttributeError, TypeError):
        return default

def create_canvas_factory(client_name, report_date):
    """Factory function to create canvas with proper metadata"""
    def canvas_factory(filename, **kwargs):
        canvas_instance = NumberedCanvas(filename, **kwargs)
        canvas_instance.client_name = client_name
        canvas_instance.report_date = report_date
        return canvas_instance
    return canvas_factory

def generate_pasta_pdf_report(tm_obj, pasta_data):
    """
    Generates a professional PASTA threat model report in PDF format.
    """
    buffer = BytesIO()
    temp_files_to_cleanup = []  # Track temp files for cleanup after PDF generation

    # Create document with increased bottom margin for footer
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=100  # Increased for footer space
    )
    
    # Safely extract metadata with fallbacks
    client_name = safe_get_attribute(tm_obj, 'client_name', 'Unknown Client')
    app_name = safe_get_attribute(tm_obj, 'app_name', 'Unknown Application')
    assessment_name = safe_get_attribute(tm_obj, 'assessment_name', 'Security Assessment')
    
    # Fix date issue - provide current date if last_analysis_at is None or missing
    report_date = safe_get_attribute(tm_obj, 'last_analysis_at', None)
    if report_date == "N/A" or not report_date:
        report_date = datetime.now().strftime('%Y-%m-%d')

    # Store for canvas use
    doc.client_name = client_name
    doc.report_date = report_date

    # --- Enhanced Styles ---
    styles = getSampleStyleSheet()
    
    # Custom styles for professional appearance
    styles.add(ParagraphStyle(
        name="TitleCenter", 
        fontSize=24, 
        alignment=TA_CENTER, 
        textColor=colors.HexColor("#003366"), 
        spaceAfter=30,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name="SectionHeader", 
        fontSize=16, 
        textColor=colors.HexColor("#005f73"), 
        spaceBefore=20, 
        spaceAfter=12, 
        leading=20,
        fontName='Helvetica-Bold',
        keepWithNext=1
    ))
    
    styles.add(ParagraphStyle(
        name="SubSectionHeader", 
        fontSize=14, 
        textColor=colors.HexColor("#0a9396"), 
        spaceBefore=15, 
        spaceAfter=8, 
        leading=16,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name="NormalJustify", 
        parent=styles['Normal'], 
        alignment=TA_JUSTIFY, 
        fontSize=10, 
        leading=14,
        spaceAfter=6
    ))
    
    styles.add(ParagraphStyle(
        name="BulletPoint", 
        parent=styles['Normal'], 
        alignment=TA_LEFT, 
        fontSize=9, 
        leading=13, 
        leftIndent=20,
        spaceAfter=3
    ))

    story = []

    # --- Enhanced Cover Page ---
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("PASTA Threat Model Report", styles["TitleCenter"]))
    story.append(Spacer(1, 0.3*inch))
    
    # Professional cover page information
    cover_info = [
        f"<b>Application:</b> {app_name}",
        f"<b>Client:</b> {client_name}",
        f"<b>Assessment:</b> {assessment_name}",
        f"<b>Report Date:</b> {report_date}",
        f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ]
    
    for info in cover_info:
        story.append(Paragraph(info, styles["NormalJustify"]))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(Spacer(1, 0.5*inch))
    
    # Add executive summary box on cover
    exec_summary_text = """
    <b>Executive Summary:</b><br/>
    This report presents a comprehensive threat model analysis using the PASTA (Process for Attack 
    Simulation and Threat Analysis) methodology. The analysis identifies security threats, evaluates 
    risks, and provides actionable mitigation strategies aligned with industry standards.
    """
    story.append(Paragraph(exec_summary_text, styles["NormalJustify"]))
    story.append(PageBreak())

    # --- Table of Contents ---
    # toc = TableOfContents()
    # toc.levelStyles = [
    #     ParagraphStyle(fontSize=12, name="TOCHeading1", leftIndent=20, spaceBefore=5, 
    #                   textColor=colors.HexColor("#005f73"), fontName='Helvetica-Bold'),
    #     ParagraphStyle(fontSize=10, name="TOCHeading2", leftIndent=40, spaceBefore=2,
    #                   fontName='Helvetica'),
    # ]
    
    # story.append(Paragraph("Table of Contents", styles["SectionHeader"]))
    # story.append(Spacer(1, 0.2*inch))
    # story.append(toc)
    # story.append(PageBreak())

    # --- Business and Technical Context ---
    context_header = Paragraph("Business and Technical Context", styles["SectionHeader"])
    story.append(context_header)
    toc.addEntry(0, "Business and Technical Context", 1)
    
    # Safely get context data
    try:
        context_data = tm_obj.get_context_summary()
    except AttributeError:
        context_data = {
            'app_name': app_name,
            'client_name': client_name,
            'assessment_name': assessment_name
        }
    
    # Create context table for better presentation
    context_table_data = [['Context Element', 'Value']]
    for key, value in context_data.items():
        display_key = key.replace('_', ' ').title()
        display_value = json.dumps(value, indent=2) if isinstance(value, dict) else str(value)
        context_table_data.append([
            Paragraph(display_key, styles["NormalJustify"]),
            Paragraph(display_value, styles["NormalJustify"])
        ])
    
    context_table = Table(context_table_data, colWidths=[2*inch, 4.5*inch])
    context_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#005f73")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ]))
    story.append(context_table)
    story.append(PageBreak())

    # --- Threat Analysis (STRIDE) ---
    threats_header = Paragraph("Threat Analysis", styles["SectionHeader"])
    story.append(threats_header)
    toc.addEntry(0, "Threat Analysis (STRIDE)", 2)
    
    stride_data = pasta_data.get('threat_model', {}).get('threat_model', [])
    if stride_data:
        # Enhanced STRIDE table with better formatting
        stride_data = pasta_data.get('threat_model', {}).get('threat_model', [])
        stride_table_data = [['Threats', 'Mitigations']]

        for threat in stride_data:
            if isinstance(threat, dict):
                threats_text = format_list_items(threat.get('Threats', []), styles)
                mitigations_text = format_list_items(threat.get('Mitigations', []), styles)

                stride_table_data.append([
                    Paragraph(threats_text, styles["BulletPoint"]),
                    Paragraph(mitigations_text, styles["BulletPoint"])
                ])

        stride_table = Table(stride_table_data, colWidths=[3.5*inch, 3*inch])
        stride_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#005f73")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,1), (-1,-1), 9),
        ]))
        story.append(stride_table)
    else:
        story.append(Paragraph("No STRIDE threat data available.", styles["NormalJustify"]))
    story.append(PageBreak())

    # --- Control Matrix ---
    controls_header = Paragraph("Control Matrix", styles["SectionHeader"])
    story.append(controls_header)
    toc.addEntry(0, "Control Matrix", 3)
    
    control_data = pasta_data.get('security_controls', {}).get('control_matrix', [])
    if control_data:
        control_table_data = [['CCM ID', 'Control', 'ISO Ref', 'NIST Ref']]
        for control in control_data:
            control_table_data.append([
                Paragraph(control.get('CCM Control ID', 'N/A'), styles["NormalJustify"]),
                Paragraph(control.get('Control Description', 'N/A'), styles["NormalJustify"]),
                Paragraph(control.get('ISO 27001 reference', 'N/A'), styles["NormalJustify"]),
                Paragraph(control.get('NIST 800-53 reference', 'N/A'), styles["NormalJustify"])
            ])
        control_table = Table(control_table_data, colWidths=[1*inch, 3.2*inch, 1.2*inch, 1.1*inch])
        control_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#005f73")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,1), (-1,-1), 8),  # Smaller font for better fit
        ]))
        story.append(control_table)
    else:
        story.append(Paragraph("No control matrix data available.", styles["NormalJustify"]))
    story.append(PageBreak())

    # --- Risk & Impact Analysis (DREAD) ---
    risk_header = Paragraph("Risk & Impact Analysis (DREAD)", styles["SectionHeader"])
    story.append(risk_header)  
    toc.addEntry(0, "Risk & Impact Analysis (DREAD)", 5)
    
    dread_data = pasta_data.get('risk_analysis', {}).get('dread_assessment', {}).get('Risk Assessment', [])
    if dread_data:
        dread_table_data = [['Threat Type', 'Scenario', 'D', 'R', 'E', 'A', 'D', 'Score']]
        
        for item in dread_data:
            if isinstance(item, dict):
                score = (
                    item.get('Damage Potential', 0)
                    + item.get('Reproducibility', 0)
                    + item.get('Exploitability', 0)
                    + item.get('Affected Users', 0)
                    + item.get('Discoverability', 0)
                ) / 5
                
                # Create individual row for each threat scenario
                dread_table_data.append([
                    Paragraph(item.get('Threat Type', 'N/A'), styles["NormalJustify"]),
                    Paragraph(item.get('Scenario', 'N/A')[:100] + "..." if len(item.get('Scenario', '')) > 100 else item.get('Scenario', 'N/A'), styles["NormalJustify"]),
                    str(item.get('Damage Potential', 0)),
                    str(item.get('Reproducibility', 0)),
                    str(item.get('Exploitability', 0)),
                    str(item.get('Affected Users', 0)),
                    str(item.get('Discoverability', 0)),
                    f"{score:.1f}"
                ])
        
        dread_table = Table(dread_table_data, colWidths=[1*inch, 2.2*inch, 0.4*inch, 0.4*inch, 0.4*inch, 0.4*inch, 0.4*inch, 0.6*inch])
        dread_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#005f73")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('ALIGN', (0,1), (1,-1), 'LEFT'),  # Left align first two columns
            ('FONTSIZE', (0,1), (-1,-1), 8),  # Smaller font for content
        ]))
        story.append(dread_table)
    else:
        story.append(Paragraph("No DREAD risk analysis data available.", styles["NormalJustify"]))

    # Add summary and recommendations section
    story.append(PageBreak())
    summary_header = Paragraph("Summary and Recommendations", styles["SectionHeader"])
    story.append(summary_header)
    toc.addEntry(0, "Summary and Recommendations", 6)
    
    # Calculate some basic statistics
    total_threats = len(dread_data) if dread_data else 0
    high_risk_threats = len([item for item in dread_data if isinstance(item, dict) and 
                           (item.get('Damage Potential', 0) + item.get('Reproducibility', 0) + 
                            item.get('Exploitability', 0) + item.get('Affected Users', 0) + 
                            item.get('Discoverability', 0)) / 5 >= 7.0]) if dread_data else 0
    
    summary_text = f"""
    <b>Assessment Summary:</b><br/>
    • Total threats identified: {total_threats}<br/>
    • High-risk threats (score ≥ 7.0): {high_risk_threats}<br/>
    • Analysis completed: {report_date}<br/><br/>
    
    <b>Key Recommendations:</b><br/>
    • Implement multi-factor authentication for all user accounts<br/>
    • Establish comprehensive logging and monitoring<br/>
    • Regular security assessments and penetration testing<br/>
    • Employee security awareness training<br/>
    • Incident response plan development and testing
    """
    
    story.append(Paragraph(summary_text, styles["NormalJustify"]))

    try:
        # Use multiBuild for proper TOC generation with custom canvas
        canvas_factory = create_canvas_factory(client_name, report_date)
        doc.multiBuild(story, canvasmaker=canvas_factory)
        
        pdf_content = buffer.getvalue()
        buffer.close()
        
        return pdf_content
        
    finally:
        # Clean up temporary files after PDF generation is complete
        for temp_file in temp_files_to_cleanup:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except OSError as e:
                # Log but don't fail - cleanup errors shouldn't break the main process
                print(f"Warning: Failed to cleanup temp file {temp_file}: {e}")