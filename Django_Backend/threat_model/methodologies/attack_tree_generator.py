import os
import re
import json
import logging
import shutil
import subprocess
import tempfile
from io import BytesIO
from openai import OpenAI
from PIL import Image as PILImage

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

logger = logging.getLogger(__name__)

def diagnose_mermaid_setup():
    """
    Diagnostic function to check Mermaid CLI setup and capabilities.
    """
    logger.info("=== Mermaid CLI Diagnostics ===")
    
    # Check if mmdc is in PATH
    mmdc_path = shutil.which("mmdc")
    if not mmdc_path:
        logger.error("ISSUE: Mermaid CLI (mmdc) not found in PATH")
        logger.error("SOLUTION: Install with 'npm install -g @mermaid-js/mermaid-cli'")
        return False
    
    logger.info(f"✓ Found mmdc at: {mmdc_path}")
    
    # Check version
    try:
        version_result = subprocess.run([mmdc_path, "--version"], capture_output=True, text=True, timeout=10)
        if version_result.returncode == 0:
            logger.info(f"✓ Mermaid CLI version: {version_result.stdout.strip()}")
        else:
            logger.warning(f"⚠ Version check failed: {version_result.stderr}")
    except Exception as e:
        logger.warning(f"⚠ Could not check version: {e}")
    
    # Test with simple diagram
    test_mermaid = "graph TD\n    A[Test] --> B[Node]"
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.mmd') as f:
            f.write(test_mermaid)
            test_input = f.name
            
        test_output = test_input.replace('.mmd', '.png')
        
        test_cmd = [mmdc_path, "-i", test_input, "-o", test_output, "-w", "800", "-b", "white"]
        result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and os.path.exists(test_output):
            logger.info("✓ Basic Mermaid rendering test passed")
            # Check image validity
            try:
                with PILImage.open(test_output) as img:
                    w, h = img.size
                    logger.info(f"✓ Generated test image: {w}x{h} pixels")
            except Exception as img_e:
                logger.error(f"✗ Test image corrupted: {img_e}")
        else:
            logger.error(f"✗ Basic rendering test failed: {result.stderr}")
            return False
            
        # Cleanup
        for path in [test_input, test_output]:
            if os.path.exists(path):
                os.remove(path)
                
    except Exception as e:
        logger.error(f"✗ Test rendering failed: {e}")
        return False
    
    logger.info("=== Mermaid CLI Diagnostics Complete ===")
    return True

# --- Core Attack Tree Generation ---

def _create_attack_tree_prompt(threat_model):
    """
    Creates a dynamic user prompt by leveraging STRIDE analysis results
    if they are available on the threat_model object.
    """
    # 1. Get the basic application context.
    context = threat_model.get_context_summary()
    
    # 2. Safely access the detailed STRIDE threats.
    stride_threats = []
    if threat_model.threat_model_data and 'threat_model' in threat_model.threat_model_data:
        threat_list = threat_model.threat_model_data.get('threat_model', [])
        for threat in threat_list:
            stride_threats.append({
                "threat_type": threat.get("threat_type"),
                "scenario": threat.get("scenario"),
                "attack_vector": threat.get("attack_vector")
            })

    # 3. Build the enhanced prompt string, providing all necessary context.
    prompt = f"""
Please generate an attack tree based on the following information.

**Application Context:**
A {context.get('deployment', 'N/A')} application named {threat_model.app_name} that handles {context.get('data_classification', 'N/A')} data. It is internet-facing: {context.get('internet_facing', 'N/A')}. Authentication methods include: {context.get('authentication', 'N/A')}. Technology stack includes: {json.dumps(context.get('technology_stack'), indent=2)}.
"""

    if stride_threats:
        prompt += f"""
**Identified STRIDE Threats:**
A prior analysis has identified the following specific threats. **You must use these threats as the primary basis for the attack paths in the tree.**
{json.dumps(stride_threats, indent=2)}
"""
    else:
        prompt += """
**Identified STRIDE Threats:**
No specific pre-identified threats were provided. Generate a general attack tree based on the application context and common vulnerabilities associated with its technology stack.
"""
    
    return prompt

def _create_json_structure_prompt():
    """
    Creates the system prompt instructing the AI to return JSON, now with more detailed rules.
    """
    return """Your task is to analyze the application context and create a detailed, hierarchical attack tree in a structured JSON format. The tree must map potential attack paths from initial access to the final objective.

**Rules for the Attack Tree Content & Structure:**
- The root node must represent the ultimate goal of an attacker (e.g., "Compromise Application and Exfiltrate Sensitive Data").
- The main branches directly under the root should represent different, high-level attack strategies.
- The attack paths must be based on the specific threats identified in the user's prompt (if provided).
- The tree must show a mix of technical and social engineering attack vectors where applicable.

**Rules for the JSON Output:**
- Each node must have a unique alphanumeric `id` (e.g., "A1", "B1", "C1").
- Each node must have a clear `label` describing the specific attack step. Where applicable, include the relevant MITRE ATT&CK technique ID (e.g., "Phishing (T1566)").
- Nodes must be nested correctly under their parent's `children` array to form logical attack paths.
- Keep the tree reasonably sized (max 4 levels deep) for optimal visualization.
- **You MUST ONLY RESPOND WITH THE JSON STRUCTURE, with no additional text or explanations.**
"""

def _clean_json_response(response_text):
    """Cleans the raw AI response to extract the JSON content."""
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    first_brace = response_text.find('{')
    last_brace = response_text.rfind('}')
    if first_brace != -1 and last_brace != -1:
        return response_text[first_brace:last_brace+1]
        
    return response_text.strip()

def _convert_tree_to_mermaid(tree_data):
    """Converts the structured JSON from the AI into Mermaid diagram syntax optimized for vertical layout."""
    mermaid_lines = ["flowchart TD"]
    mermaid_lines.append("    %% Attack Tree for Healthcare Application")
    
    def process_node(node, parent_id=None, level=0):
        if not isinstance(node, dict) or "id" not in node or "label" not in node:
            logger.warning(f"Invalid node structure: {node}")
            return
            
        node_id = node["id"]
        node_label = node["label"]
        
        # Truncate long labels to prevent width issues
        if len(node_label) > 60:
            node_label = node_label[:57] + "..."
        
        # Escape quotes and format for Mermaid
        node_label_escaped = node_label.replace('"', "'")
        
        # Use different shapes for different levels
        if level == 0:
            mermaid_lines.append(f'    {node_id}["{node_label_escaped}"]')
        elif level == 1:
            mermaid_lines.append(f'    {node_id}("{node_label_escaped}")')
        else:
            mermaid_lines.append(f'    {node_id}["{node_label_escaped}"]')
        
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')
        
        if "children" in node and node["children"]:
            for child in node["children"]:
                process_node(child, node_id, level + 1)
    
    # Handle different JSON structures
    nodes_to_process = []
    
    if isinstance(tree_data, dict):
        if "nodes" in tree_data:
            # Structure: {"nodes": [...]}
            nodes_to_process = tree_data["nodes"]
        elif "id" in tree_data and "label" in tree_data:
            # Structure: {"id": "A1", "label": "...", "children": [...]} - SINGLE ROOT NODE
            nodes_to_process = [tree_data]
        elif "root" in tree_data:
            # Structure: {"root": {...}}
            nodes_to_process = [tree_data["root"]]
        elif "attack_tree" in tree_data:
            # Structure: {"attack_tree": {...}}
            attack_tree_data = tree_data["attack_tree"]
            nodes_to_process = attack_tree_data if isinstance(attack_tree_data, list) else [attack_tree_data]
        else:
            # Fallback: assume the entire object is a single root node
            nodes_to_process = [tree_data]
    elif isinstance(tree_data, list):
        # Structure: [{...}, {...}] - ARRAY OF ROOT NODES
        nodes_to_process = tree_data
    else:
        logger.error(f"Unexpected tree_data type: {type(tree_data)}")
        return "flowchart TD\n    A[\"Error: Invalid tree structure\"]"
    
    # Process all root nodes
    if not nodes_to_process:
        logger.warning("No nodes found in tree data")
        mermaid_lines.append('    A["No attack tree data available"]')
    else:
        logger.info(f"Processing {len(nodes_to_process)} root nodes")
        for root_node in nodes_to_process:
            process_node(root_node)
    
    # Add styling for better visualization
    mermaid_lines.append("")
    mermaid_lines.append("    %% Styling")
    mermaid_lines.append("    classDef default fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:#000")
    
    result = "\n".join(mermaid_lines)
    logger.info(f"Generated Mermaid with {len(mermaid_lines)} lines")
    return result

def generate_attack_tree_mermaid(api_key, model_name, threat_model):
    """
    Main function to generate the attack tree in Mermaid format using the two-step process.
    """
    client = OpenAI(api_key=api_key)
    system_prompt = _create_json_structure_prompt()
    user_prompt = _create_attack_tree_prompt(threat_model)

    logger.info(f"System prompt: {system_prompt[:200]}...")
    logger.info(f"User prompt: {user_prompt}")

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=4000
        )

        raw_response = response.choices[0].message.content
        logger.error(f"FULL RAW AI RESPONSE: {raw_response}")
        
        cleaned_response = _clean_json_response(raw_response)
        logger.error(f"CLEANED JSON RESPONSE: {cleaned_response}")
        
        tree_data = json.loads(cleaned_response)
        logger.error(f"PARSED JSON STRUCTURE: {json.dumps(tree_data, indent=2)}")
        
        mermaid_result = _convert_tree_to_mermaid(tree_data)
        logger.error(f"FINAL MERMAID RESULT: {mermaid_result}")
        
        return mermaid_result
        
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Failed to parse JSON for attack tree: {e}")
        logger.error(f"Raw response was: {response.choices[0].message.content}")
        # Return a fallback response instead of the raw content
        return """flowchart TD
    A["Attack Tree Generation Failed"]
    A --> B["Check logs for details"]
    B --> C["Verify AI response format"]
    
    %% Styling
    classDef default fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:#000"""
    except Exception as e:
        logger.error(f"Unexpected error in attack tree generation: {e}", exc_info=True)
        return """flowchart TD
    A["System Error"]
    A --> B["Check server logs"]
    
    %% Styling
    classDef default fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:#000"""

# --- PDF Generation & Diagram Rendering ---

def _render_mermaid_to_image(mermaid_code):
    """
    Renders MermaidJS code to a PNG image using the Mermaid CLI with optimized settings for vertical layouts.
    """
    infile_path, outfile_path, config_path = None, None, None
    try:
        # Debug: Log the mermaid content
        logger.info("Mermaid content preview:")
        preview_lines = mermaid_code.split('\n')[:10]  # First 10 lines
        for i, line in enumerate(preview_lines):
            logger.info(f"  {i+1}: {line}")
        if len(mermaid_code.split('\n')) > 10:
            line_count = len(mermaid_code.split("\n")) - 10
            logger.info(f"  ... and {line_count} more lines")

        
        # Create optimized Mermaid config for vertical flowcharts
        mermaid_config = {
            "theme": "default",
            "themeVariables": {
                "primaryColor": "#e1f5fe",
                "primaryTextColor": "#000000",
                "primaryBorderColor": "#01579b",
                "lineColor": "#01579b",
                "secondaryColor": "#f3f4f6",
                "tertiaryColor": "#ffffff"
            },
            "flowchart": {
                "nodeSpacing": 50,
                "rankSpacing": 80,
                "curve": "linear",
                "padding": 20
            }
        }
        
        # Write config to temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as temp_config:
            json.dump(mermaid_config, temp_config, indent=2)
            config_path = temp_config.name

        # Write Mermaid code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.mmd', encoding='utf-8') as infile:
            infile.write(mermaid_code)
            infile_path = infile.name
        
        outfile_path = infile_path.replace(".mmd", ".png")

        mmdc_path = shutil.which("mmdc")
        if not mmdc_path:
            logger.error("Mermaid CLI ('mmdc') not found in PATH.")
            return None

        # Optimized command for vertical flowcharts
        # Use reasonable dimensions that work well for attack trees
        command = [
            mmdc_path, "-i", infile_path, "-o", outfile_path,
            "-w", "1200",  # Reasonable width
            "-H", "1600",  # Taller height for vertical flow
            "-b", "white",
            "-s", "1.5",   # Scale factor
            "--configFile", config_path
           # Prevent CSS issues
        ]
        
        logger.info(f"Executing Mermaid command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            logger.warning(f"Primary Mermaid CLI command failed with code {result.returncode}. stderr: {result.stderr.strip()}")
            logger.info("Trying fallback command...")
            
            # Fallback to simpler command
            fallback_command = [
                mmdc_path, "-i", infile_path, "-o", outfile_path,
                "-w", "1200", "-H", "1600", "-b", "white"
            ]
            result = subprocess.run(fallback_command, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logger.error(f"Fallback Mermaid CLI also failed: {result.stderr.strip()}")
                return None

        if not os.path.exists(outfile_path):
            logger.error("Mermaid CLI reported success but PNG file not found.")
            return None

        # Validate the generated image
        try:
            with PILImage.open(outfile_path) as img:
                width, height = img.size
                logger.info(f"Generated image dimensions: {width}x{height} pixels")
                
                # Check for reasonable dimensions
                if width < 100 or height < 100:
                    logger.error(f"Generated image too small: {width}x{height}")
                    return None
                
                if width > 10000 or height > 10000:
                    logger.warning(f"Generated image very large: {width}x{height}")
                    # Resize if too large
                    max_size = (2400, 3200)
                    img.thumbnail(max_size, PILImage.Resampling.LANCZOS)
                    img.save(outfile_path, "PNG", optimize=True)
                    logger.info(f"Resized image to fit within {max_size}")
                    
        except Exception as img_e:
            logger.error(f"Image validation failed: {img_e}")
            return None

        return outfile_path
        
    except Exception as e:
        logger.exception(f"Unexpected error in _render_mermaid_to_image: {e}")
        return None
    finally:
        # Clean up temporary files (except output image)
        for path in [infile_path, config_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to delete temp file {path}: {cleanup_err}")

def _get_optimal_image_size(image_path, page_width, page_height, margin=72):
    """
    Calculate optimal image size maintaining aspect ratio while fitting within PDF page constraints.
    """
    try:
        with PILImage.open(image_path) as img:
            original_width, original_height = img.size
            
        # Available space on page (accounting for margins)
        available_width = page_width - (2 * margin)
        available_height = page_height - (3 * margin)  # Extra space for headers
        
        # Calculate aspect ratio
        aspect_ratio = original_width / original_height
        
        # Calculate size to fit within available space
        if aspect_ratio > available_width / available_height:
            # Image is relatively wide - constrain by width
            width = available_width
            height = width / aspect_ratio
        else:
            # Image is relatively tall - constrain by height
            height = available_height
            width = height * aspect_ratio
        
        # Ensure minimum readable size
        min_width, min_height = 4*inch, 3*inch
        if width < min_width:
            width = min_width
            height = width / aspect_ratio
        if height < min_height:
            height = min_height
            width = height * aspect_ratio
        
        # Final check to ensure it fits
        if width > available_width:
            width = available_width
            height = width / aspect_ratio
        if height > available_height:
            height = available_height
            width = height * aspect_ratio
            
        logger.info(f"Calculated optimal size: {width/inch:.1f}\" x {height/inch:.1f}\" (from {original_width}x{original_height}px)")
        return width, height
        
    except Exception as e:
        logger.warning(f"Could not determine image dimensions: {e}")
        return 6*inch, 8*inch  # Default size

def _parse_mermaid_attack_tree(mermaid_content):
    """
    Parse Mermaid attack tree content and extract nodes and relationships.
    This version is more robust to handle common AI-generated syntax errors.
    """
    lines = mermaid_content.strip().split('\n')
    nodes = {}
    relationships = []
    
    # Regex to find node definitions like A1.1["Label"] or B1("Label")
    # It now accepts dots in the ID: ([\w\.]+)
    node_pattern = re.compile(r'^\s*([\w\.]+)\s*(\[|\()"?([^"]+)"?(\]|\))')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('flowchart') or line.startswith('graph') or line.startswith('%%'):
            continue

        # --- Improved Node Parsing ---
        node_match = node_pattern.match(line)
        if node_match:
            node_id = node_match.group(1)
            node_label = node_match.group(3).strip()
            nodes[node_id] = node_label
            continue # Move to the next line after finding a node

        # --- Improved Relationship Parsing ---
        # Look for '-->' or just spaces between potential node IDs
        # This handles cases like "ROOT Al" as well as "C1 --> C1.1"
        rel_parts = re.split(r'\s*-->\s*|\s+-\s*|\s+', line)
        
        # Check if the parts look like valid node IDs from our pattern (allow dots)
        potential_ids = [part for part in rel_parts if re.fullmatch(r'[\w\.]+', part)]
        
        if len(potential_ids) >= 2:
            # Assume the first two valid IDs form the relationship
            source, target = potential_ids[0], potential_ids[1]
            # A simple check to avoid self-referencing from messy lines
            if source != target:
                relationships.append((source, target))

    return nodes, relationships

def _build_tree_structure(nodes, relationships):
    """
    Build a hierarchical tree structure from nodes and relationships.
    """
    children = {}
    parents = {}
    
    for source, target in relationships:
        if source not in children:
            children[source] = []
        children[source].append(target)
        parents[target] = source
    
    root_nodes = [node for node in nodes.keys() if node not in parents]
    
    return root_nodes, children

def _create_tree_table_data(node, nodes, children, level=0):
    """
    Create table data for tree structure representation.
    """
    table_data = []
    indent = "  " * level  # Reduced indent for better fitting
    node_label = nodes.get(node, node)
    
    # Extract MITRE technique if present
    mitre_match = re.search(r'T\d{4}', node_label)
    mitre_technique = mitre_match.group(0) if mitre_match else ""
    
    # Determine risk level based on tree level and content
    if level == 0:
        risk_level = "Critical"
    elif level == 1:
        risk_level = "High"
    elif level == 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    # Truncate long labels for table
    display_label = node_label
    if len(display_label) > 80:
        display_label = display_label[:77] + "..."
    
    table_data.append([
        f"{indent}{display_label}",
        mitre_technique,
        risk_level
    ])
    
    if node in children:
        for child in sorted(children[node]):  # Sort for consistent ordering
            table_data.extend(_create_tree_table_data(child, nodes, children, level + 1))
    
    return table_data

def _add_attack_tree_footer(canvas_obj, doc):
    """Custom footer for attack tree PDF."""
    canvas_obj.saveState()
    footer_text = f"Attack Tree Analysis | {getattr(doc, 'client_name', 'Client')} | Generated: {getattr(doc, 'report_date', 'N/A')}"
    canvas_obj.setFont("Helvetica-Oblique", 8)
    canvas_obj.setFillColor(colors.grey)
    canvas_obj.drawCentredString(0.5 * doc.pagesize[0], 0.5 * inch, footer_text)
    canvas_obj.restoreState()

def generate_attack_tree_pdf(tm_obj, mermaid_attack_tree):
    """
    Generate a standalone PDF document for the attack tree, including a rendered diagram.
    Uses consistent landscape orientation throughout.
    """
    buffer = BytesIO()
    
    # Use landscape orientation consistently throughout
    page_size = landscape(A4)  # 11.69" x 8.27"
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=page_size, 
        rightMargin=36, leftMargin=36, 
        topMargin=36, bottomMargin=72
    )
    
    # Add metadata to doc for footer
    doc.client_name = getattr(tm_obj, 'client_name', 'Unknown Client')
    doc.report_date = (
        tm_obj.last_analysis_at.strftime('%Y-%m-%d')
        if hasattr(tm_obj, 'last_analysis_at') and tm_obj.last_analysis_at else 'N/A'
    )
    doc.pagesize = page_size  # Make sure pagesize is available for footer
    
    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleCenter", 
        fontSize=18, 
        alignment=TA_CENTER, 
        textColor=colors.HexColor("#003366"), 
        spaceAfter=20,
        fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", 
        fontSize=12, 
        textColor=colors.HexColor("#005f73"), 
        spaceBefore=15, 
        spaceAfter=8,
        fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        name="NormalJustify", 
        parent=styles['Normal'], 
        alignment=TA_JUSTIFY, 
        fontSize=9, 
        leading=12
    ))
    styles.add(ParagraphStyle(
        name="CodeBlock", 
        parent=styles['Normal'], 
        fontSize=7, 
        leading=9, 
        fontName="Courier", 
        backColor=colors.lightgrey, 
        leftIndent=20, 
        rightIndent=20, 
        spaceBefore=8, 
        spaceAfter=8
    ))
    
    story = []
    image_path = None  # Initialize for cleanup
    
    try:
        # --- Title Page (Landscape) ---
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph("MITRE ATT&CK Attack Tree Analysis", styles["TitleCenter"]))
        story.append(Spacer(1, 0.3*inch))
        
        # Application info table - optimized for landscape
        info_data = [
            ["Application:", getattr(tm_obj, 'app_name', 'Unknown')],
            ["Client:", getattr(tm_obj, 'client_name', 'Unknown')],
            ["Assessment:", getattr(tm_obj, 'assessment_name', 'Security Assessment')],
            ["Generated:", doc.report_date]
        ]
        info_table = Table(info_data, colWidths=[1.5*inch, 5*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(info_table)
        
        # Executive Summary
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
        summary_text = f"""
        This attack tree analysis maps potential attack vectors against {getattr(tm_obj, 'app_name', 'the application')} 
        using the MITRE ATT&CK framework. The tree structure shows how an attacker might progress from initial 
        access to achieving their ultimate objective, providing a visual representation of the attack paths that 
        security controls should address.
        """
        story.append(Paragraph(summary_text, styles["NormalJustify"]))
        story.append(PageBreak())
        
        # --- Attack Tree Diagram ---
        story.append(Paragraph("Attack Tree Diagram", styles["SectionHeader"]))
        
        # Render the diagram
        image_path = _render_mermaid_to_image(mermaid_attack_tree)
        
        if image_path and os.path.exists(image_path):
            # Calculate optimal size for landscape page
            width, height = _get_optimal_image_size(
                image_path, 
                page_size[0],  # Landscape width
                page_size[1],  # Landscape height
                margin=36
            )
            
            story.append(Spacer(1, 0.1*inch))
            story.append(Image(image_path, width=width, height=height, hAlign='CENTER'))
            logger.info(f"Successfully added diagram image: {width/inch:.1f}\" x {height/inch:.1f}\"")
        else:
            error_msg = "Error: Could not render diagram image. Please check Mermaid CLI installation and configuration."
            story.append(Paragraph(f"<i>{error_msg}</i>", styles["NormalJustify"]))
            logger.error("Failed to render or locate diagram image")

        story.append(PageBreak())
        
        # --- Parse and Display Attack Tree Structure ---
        nodes, relationships = _parse_mermaid_attack_tree(mermaid_attack_tree)
        
        if nodes and relationships:
            root_nodes, children = _build_tree_structure(nodes, relationships)
            
            # Attack Tree Structure Table
            story.append(Paragraph("Attack Tree Structure", styles["SectionHeader"]))
            table_data = [["Attack Step", "MITRE ID", "Risk Level"]]
            
            for root in root_nodes:
                table_data.extend(_create_tree_table_data(root, nodes, children))
            
            # Optimize column widths for landscape
            col_widths = [6.5*inch, 1.2*inch, 1*inch]
            tree_table = Table(table_data, colWidths=col_widths)
            tree_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#005f73")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(tree_table)
            story.append(Spacer(1, 0.2*inch))
            
            # MITRE Techniques Summary
            story.append(Paragraph("MITRE ATT&CK Techniques Identified", styles["SectionHeader"]))
            mitre_techniques = {match for label in nodes.values() for match in re.findall(r'T\d{4}', label)}
            if mitre_techniques:
                techniques_text = f"This attack tree references the following MITRE ATT&CK techniques: {', '.join(sorted(mitre_techniques))}"
                story.append(Paragraph(techniques_text, styles["NormalJustify"]))
            else:
                story.append(Paragraph("No specific MITRE ATT&CK techniques were identified in the node labels.", styles["NormalJustify"]))
        
        # Raw Mermaid Code for Reference
        story.append(PageBreak())
        story.append(Paragraph("Mermaid Diagram Source Code", styles["SectionHeader"]))
        story.append(Paragraph(
            "The following Mermaid code can be used to render this attack tree in supported visualization tools:",
            styles["NormalJustify"]
        ))
        
        # Clean and format Mermaid code for display
        clean_mermaid = mermaid_attack_tree.strip().replace('\n', '<br/>')
        story.append(Paragraph(clean_mermaid, styles["CodeBlock"]))

        # Build the PDF
        doc.build(story, onLaterPages=_add_attack_tree_footer, onFirstPage=_add_attack_tree_footer)
        
        pdf_content = buffer.getvalue()
        buffer.close()
        return pdf_content

    except Exception as e:
        logger.exception(f"Error generating attack tree PDF: {e}")
        raise
        
    finally:
        # Clean up temporary image file
        if image_path and os.path.exists(image_path):
            try:
                os.remove(image_path)
                logger.info(f"Successfully cleaned up temporary file: {image_path}")
            except Exception as cleanup_e:
                logger.error(f"Failed to clean up temporary file {image_path}: {cleanup_e}")