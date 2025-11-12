# File: methodologies/pasta.py
import json
from .llm_callers import generate_json_response, generate_text_response
from .dread import create_dread_assessment_prompt, get_dread_assessment

def _create_threat_analysis_prompt(context):
    """Creates the prompt for PASTA Stage 4: Threat Analysis."""
    return f"""
Act as a cyber security expert with more than 20 years of experience using the PASTA threat modelling methodology.
Your task is to produce a list of specific threat agents and model threats based on the application context provided.
For each threat agent, list multiple threats. Prioritise threats with risk ratings and provide mitigations.

APPLICATION CONTEXT:
{json.dumps(context, indent=2)}

Use a JSON formatted response with the keys "threat_model" and "improvement_suggestions".
Under "threat_model", include an array of objects with the keys "Threat Agent", "Threats", "Risk Rating (Likelihood, Impact, Risk Level)", and "Mitigations".
"""

def _create_control_analysis_prompt(context):
    """Creates the prompt for PASTA Stage 5: Control Analysis."""
    return f"""
Act as a cyber security expert with experience using ISO 27001, NIST 800-53 and the Cloud Security Alliance CCM matrix.
Provide a list of security controls as per the CCM matrix, aligning with ISO 27001 and NIST 800-53, tailored to the application context.

APPLICATION CONTEXT:
{json.dumps(context, indent=2)}

Provide the control matrix in a JSON formatted response with the key "control_matrix".
Under "control_matrix", include an array of objects with the keys "CCM Control ID", "Control Description", "Questionnaires", "ISO 27001 reference", and "NIST 800-53 reference".
"""

def _create_attack_tree_prompt(context, threats_data):
    """Creates the prompt for PASTA Stage 6: Attack Tree Generation with MITRE mapping."""
    return f"""
Act as a cybersecurity expert specializing in attack modeling using MITRE ATT&CK framework.

Create a hierarchical attack tree in Mermaid syntax that shows how an attacker could achieve their primary objective against this application.

APPLICATION CONTEXT:
{json.dumps(context, indent=2)}

IDENTIFIED THREATS:
{json.dumps(threats_data, indent=2)}

Requirements for the attack tree:
1. Start with ONE clear attacker objective at the root (e.g., "Exfiltrate Customer Data" or "Gain Administrative Access")
2. Create a true hierarchical tree structure showing alternative paths to achieve this goal
3. Base the attack paths on the specific threats identified in the threat analysis above
4. Include MITRE ATT&CK technique IDs where applicable (e.g., T1566 for Phishing)
5. Use proper Mermaid flowchart syntax with clear parent-child relationships
6. Show both technical and social engineering attack vectors
7. Each branch should represent a different attack strategy

The tree should demonstrate how the identified threats can be chained together to achieve the attacker's ultimate goal.
"""

def generate_pasta_report_data(api_key, model_name, context, llm_provider="openai"):
    """
    Generates the data for a full, multi-stage PASTA threat model report.
    """
    # --- Stage 4: Threat Analysis ---
    threat_analysis_prompt = _create_threat_analysis_prompt(context)
    threat_analysis_result = generate_json_response(
        provider=llm_provider, api_key=api_key, model_name=model_name,
        system_prompt="You are a helpful assistant designed to output JSON.",
        user_prompt=threat_analysis_prompt
    )

    # --- Stage 5: Control Analysis ---
    control_analysis_prompt = _create_control_analysis_prompt(context)
    control_analysis_result = generate_json_response(
        provider=llm_provider, api_key=api_key, model_name=model_name,
        system_prompt="You are a helpful assistant designed to output JSON.",
        user_prompt=control_analysis_prompt
    )

    # --- Stage 6: Attack Tree (now connected to threat analysis) ---
    # threats_for_tree = threat_analysis_result.get("threat_model", [])
    # attack_tree_prompt = _create_attack_tree_prompt(context, threats_for_tree)
    # attack_tree_system_prompt = """As a cybersecurity expert, create a MITRE ATT&CK based attack tree in Mermaid syntax. 
    # Create a true hierarchical tree with one root objective and branching attack paths.
    # You MUST only respond with the Mermaid code block."""
    # attack_tree_result = generate_text_response(
    #     provider=llm_provider, api_key=api_key, model_name=model_name,
    #     system_prompt=attack_tree_system_prompt,
    #     user_prompt=attack_tree_prompt
    # )
    
    # --- DREAD Risk Analysis ---        
    threats_for_dread = threat_analysis_result.get("threat_model", [])
    dread_prompt = create_dread_assessment_prompt(json.dumps(threats_for_dread, indent=2))
    
    dread_assessment_result = get_dread_assessment(
        api_key=api_key,
        model_name=model_name,
        prompt=dread_prompt,
        llm_provider=llm_provider
    )
    risk_analysis_result = {"dread_assessment": dread_assessment_result}

    # --- Assemble the Full Report Data ---
    full_report_data = {
        "threat_model": threat_analysis_result,
        "security_controls": control_analysis_result,
        # "mitre_attack_tree": attack_tree_result,
        "risk_analysis": risk_analysis_result
    }
    
    return full_report_data