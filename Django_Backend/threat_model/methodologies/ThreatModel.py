import json
from ..models import ThreatModel
from ..processing.faiss_search import search_faiss  # <-- You'll implement this to query FAISS
from datetime import datetime,timezone  
from functools import lru_cache # For caching
from .llm_callers import generate_json_response # <-- Use the new abstracted service



def create_enhanced_threat_model_prompt(threat_model_obj, retrieved_context):
    """
    Create a comprehensive threat modeling prompt using the enhanced ThreatModel fields.
    
    Args:
        threat_model_obj (ThreatModel): The ThreatModel instance with context
        retrieved_context (str): Retrieved context from FAISS search
        
    Returns:
        str: Formatted prompt for the LLM
    """
    context_summary = threat_model_obj.get_context_summary()
    
    return f"""
Act as a cyber security expert with 20+ years experience using the STRIDE threat modelling methodology.
Analyze the provided documentation and system context to produce comprehensive, specific threats.

SYSTEM INFORMATION:
- Application: {threat_model_obj.app_name}
- Client: {threat_model_obj.client_name}  
- Authentication: {context_summary['authentication']}
- Internet Facing: {context_summary['internet_facing']}
- Handles Sensitive Data: {context_summary['sensitive_data']}
- Data Classification: {context_summary['data_classification']}
- Deployment Environment: {context_summary['deployment']}
- Compliance Requirements: {context_summary['compliance']}
- User Types: {context_summary['user_types']}
- Third-party Integrations: {context_summary['integrations']}
- Critical Assets: {context_summary['critical_assets']}
- Technology Stack: {json.dumps(context_summary['technology_stack'], indent=2)}

INSTRUCTIONS:
For each STRIDE category, provide AT LEAST 3 credible, specific threats based on the system context:

1. **Spoofing**: Identity verification bypass, authentication weaknesses
2. **Tampering**: Data integrity attacks, unauthorized modifications  
3. **Repudiation**: Non-repudiation failures, logging/audit bypass
4. **Information Disclosure**: Data exposure, unauthorized access to sensitive information
5. **Denial of Service**: Availability attacks, resource exhaustion
6. **Elevation of Privilege**: Authorization bypass, privilege escalation

For each threat, include:
- **Threat ID**: A unique identifier in the format 'APPNAME-STRIDE-00X' (e.g., '{threat_model_obj.app_name}-S-001').
- **Threat Type**: STRIDE category
- **Scenario**: Detailed attack scenario specific to this system
- **Attack Vector**: How the threat would be executed
- **Impact (Severity)**: Business and technical impact (High/Medium/Low)
- **Likelihood**: Probability based on system characteristics (High/Medium/Low)
- **Affected Components**: Specific system components at risk
- **Mitigation Suggestion**: A concise, actionable recommendation for developers to fix the issue.

Focus on threats that are:
- Specific to the documented system architecture and technology stack
- Realistic given the deployment environment and user access patterns
- Aligned with the compliance and regulatory context
- Proportional to the data sensitivity and classification level

RETRIEVED SYSTEM DOCUMENTATION:
{retrieved_context}

Output as valid JSON with this structure:
{{
  "threat_model": [
    {{
      "threat_id": "{threat_model_obj.app_name}-S-001",
      "threat_type": "Spoofing",
      "scenario": "Detailed scenario description",
      "attack_vector": "Specific attack method",
      "potential_impact": "High/Medium/Low with explanation",
      "likelihood": "High/Medium/Low with justification", 
      "affected_components": ["component1", "component2"],
      "mitigation_suggestion": "Implement multi-factor authentication and strict validation of all authentication tokens."
    }}
  ],
  "executive_summary": {{
    "total_threats": 0,
    "critical_threats": 0,
    "high_risk_areas": ["area1", "area2"],
    "top_recommendations": ["rec1", "rec2", "rec3"]
  }},
  "improvement_suggestions": [
    "Specific suggestions for additional context or documentation needed"
  ],
  "confidence_metrics": {{
    "overall_confidence": 0.85,
    "context_completeness": 0.75,
    "threat_coverage": 0.90
  }}
}}
"""


def assess_context_quality(threat_model_obj, retrieved_chunks):
    """
    Assess the quality and completeness of available context for threat modeling.
    
    Args:
        threat_model_obj (ThreatModel): The ThreatModel instance
        retrieved_chunks (list): Retrieved context chunks from FAISS
        
    Returns:
        dict: Quality assessment metrics
    """
    assessment = {
        'context_completeness': threat_model_obj.get_context_completeness(),
        'document_coverage': 0.0,
        'architecture_clarity': 0.0,
        'technical_depth': 0.0,
        'security_context': 0.0
    }
     # Get total document count directly from the full FAISS metadata for accuracy
    try:
        total_docs_in_index = threat_model_obj.get_total_docs_from_faiss_metadata()
    except FileNotFoundError:
        total_docs_in_index = threat_model_obj.documents.count() # Fallback
    if not retrieved_chunks:
        return assessment
    
    # Analyze retrieved content
    all_text = " ".join([chunk.get('chunk_text', '') for chunk in retrieved_chunks])
    text_lower = all_text.lower()
    
    # Document coverage score
    unique_files_retrieved = len(set(chunk['filename'] for chunk in retrieved_chunks))
    assessment['document_coverage'] = min(unique_files_retrieved / max(total_docs_in_index, 1), 1.0)
    
    # Architecture clarity - look for architectural terms
    arch_terms = ['architecture', 'component', 'service', 'database', 'api', 'interface', 
                  'workflow', 'diagram', 'flow', 'integration', 'deployment']
    arch_score = sum(1 for term in arch_terms if term in text_lower) / len(arch_terms)
    assessment['architecture_clarity'] = min(arch_score, 1.0)
    
    # Technical depth - look for technical implementation details  
    tech_terms = ['authentication', 'authorization', 'encryption', 'ssl', 'tls', 'jwt',
                  'session', 'token', 'certificate', 'firewall', 'load balancer', 'cache']
    tech_score = sum(1 for term in tech_terms if term in text_lower) / len(tech_terms)
    assessment['technical_depth'] = min(tech_score, 1.0)
    
    # Security context - look for security-related content
    security_terms = ['security', 'threat', 'risk', 'vulnerability', 'attack', 'breach',
                      'compliance', 'audit', 'policy', 'control', 'protection', 'privacy']
    security_score = sum(1 for term in security_terms if term in text_lower) / len(security_terms)
    assessment['security_context'] = min(security_score, 1.0)
    
    return assessment

@lru_cache(maxsize=32)
def _cached_faiss_search(threat_model_id, query, top_k):
    """A cached wrapper around the search function."""
    return search_faiss(threat_model_id, query, top_k=top_k)


def get_stride_threat_model_from_index(threat_model_id, api_key, model_name="gpt-4.1", llm_provider="openai"):
    """
    Retrieves relevant data from FAISS and generates an enhanced STRIDE threat model
    using an abstracted LLM service.
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
    except ThreatModel.DoesNotExist:
        raise ValueError(f"ThreatModel ID {threat_model_id} not found.")

    tm_obj.status = ThreatModel.StatusChoices.PROCESSING
    tm_obj.save()

    try:
        # 1. Dynamically generate the query from context
        query = f"STRIDE threat model for {tm_obj.app_name} application architecture, authentication, and data handling security design"

        # 2. Use the cached search function to retrieve chunks
        chunks = _cached_faiss_search(threat_model_id, query, top_k=15)
        
        if not chunks:
            raise ValueError("No relevant context found in FAISS index. Ensure documents are processed.")
        
        # 3. Build context string using the corrected 'chunk_text' key
        context_text = "\n\n--- DOCUMENT SECTION ---\n".join([
            f"File: {chunk['filename']}\n{chunk.get('chunk_text', '')}" 
            for chunk in chunks
        ])
        
        # 4. Assess context quality
        quality_assessment = assess_context_quality(tm_obj, chunks)
        tm_obj.context_completeness = quality_assessment['context_completeness']
        
        # 5. Build the prompts for the LLM
        prompt = create_enhanced_threat_model_prompt(tm_obj, context_text)
        system_prompt = "You are an expert cybersecurity consultant specializing in STRIDE threat modeling. Generate comprehensive, actionable threat models in valid JSON format."
        
        # 6. Call the abstracted and robust LLM service
        output_json = generate_json_response(
            provider=llm_provider,
            api_key=api_key,
            model_name=model_name,
            system_prompt=system_prompt,
            user_prompt=prompt
        )
        
        # 7. Enhance output with metadata
        output_json['analysis_metadata'] = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'model_used': model_name,
            'llm_provider': llm_provider,
            'context_quality': quality_assessment,
            'chunks_analyzed': len(chunks),
            'unique_documents': len(set(chunk['filename'] for chunk in chunks)),
            'query_used': query
        }
        
        # 8. Calculate confidence score
        confidence_metrics = output_json.get('confidence_metrics', {})
        tm_obj.confidence_score = confidence_metrics.get('overall_confidence', 0.7)
        
        # 9. Save to database
        tm_obj.threat_model_data = output_json
        tm_obj.last_analysis_at = datetime.now(timezone.utc)
        tm_obj.status = ThreatModel.StatusChoices.COMPLETED
        tm_obj.save()
        
        print(f"[ThreatModel] Successfully generated threat model for {tm_obj.app_name}")
        print(f"[ThreatModel] Confidence: {tm_obj.confidence_score:.2f}, Context Completeness: {tm_obj.context_completeness:.2f}")
        
        return output_json
        
    except Exception as e:
        # Update status on failure
        tm_obj.status = ThreatModel.StatusChoices.FAILED
        tm_obj.save()
        print(f"[ThreatModel] Error generating threat model: {str(e)}")
        raise


def regenerate_threat_model_with_feedback(threat_model_id, feedback, api_key, model_name="gpt-4.1", llm_provider="openai"):
    """
    Regenerate threat model incorporating user feedback using the abstracted LLM service.
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
        previous_model = tm_obj.threat_model_data
        
        query = previous_model.get('analysis_metadata', {}).get('query_used', 'threat model security architecture')
        
        # Use the cached search to get fresh context
        chunks = _cached_faiss_search(threat_model_id, query, top_k=15)
        context_text = "\n\n--- DOCUMENT SECTION ---\n".join([
            f"File: {chunk['filename']}\n{chunk.get('chunk_text', '')}" 
            for chunk in chunks
        ])
        
        # Create the prompts
        base_prompt = create_enhanced_threat_model_prompt(tm_obj, context_text)
        user_feedback_prompt = f"""
{base_prompt}

PREVIOUS ANALYSIS FEEDBACK:
The previous threat model has been reviewed and the following feedback was provided:
{feedback}

Please incorporate this feedback to improve the threat model. Focus on addressing the specific concerns raised while maintaining comprehensive STRIDE coverage.
"""
        system_prompt = "You are an expert cybersecurity consultant. Improve the threat model based on provided feedback while maintaining comprehensive STRIDE methodology coverage."

        # Use the new abstracted LLM caller
        output_json = generate_json_response(
            provider=llm_provider,
            api_key=api_key,
            model_name=model_name,
            system_prompt=system_prompt,
            user_prompt=user_feedback_prompt
        )
        
        # Add regeneration metadata
        output_json['analysis_metadata'] = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'model_used': model_name,
            'regenerated_from_feedback': True,
            'feedback_incorporated': feedback,
            'previous_analysis_at': previous_model.get('analysis_metadata', {}).get('generated_at')
        }
        
        # Save updated model
        tm_obj.threat_model_data = output_json
        tm_obj.last_analysis_at = datetime.now(timezone.utc)
        tm_obj.save()
        
        return output_json
        
    except Exception as e:
        print(f"[ThreatModel] Error regenerating threat model: {str(e)}")
        raise


def export_threat_model_report(threat_model_id, format='json'):
    """
    Export threat model in various formats for reporting.
    
    Args:
        threat_model_id (int): ThreatModel database ID
        format (str): Export format ('json', 'markdown', 'csv')
        
    Returns:
        str: Formatted report content
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
        threat_data = tm_obj.threat_model_data
        
        if not threat_data:
            raise ValueError("No threat model data available for export.")
        
        if format == 'json':
            return json.dumps(threat_data, indent=2, default=str)
        
        elif format == 'markdown':
            return _generate_markdown_report(tm_obj, threat_data)
        
        elif format == 'csv':
            return _generate_csv_report(threat_data)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
            
    except ThreatModel.DoesNotExist:
        raise ValueError(f"ThreatModel ID {threat_model_id} not found.")


def _generate_markdown_report(tm_obj, threat_data):
    """Generate a markdown report from threat model data."""
    
    context_summary = tm_obj.get_context_summary()
    threats = threat_data.get('threat_model', [])
    executive_summary = threat_data.get('executive_summary', {})
    confidence_str=f"{tm_obj.confidence_score:.2f}" if tm_obj.confidence_score is not None else "N/A"
    md_content = f"""# Threat Model Report
    
## System Overview
- **Application**: {tm_obj.app_name}
- **Client**: {tm_obj.client_name}
- **Assessment**: {tm_obj.assessment_name}
- **Generated**: {tm_obj.last_analysis_at.strftime('%Y-%m-%d %H:%M:%S') if tm_obj.last_analysis_at else 'N/A'}
- **Confidence Score**: {confidence_str}

## System Context
- **Authentication**: {context_summary['authentication']}
- **Internet Facing**: {context_summary['internet_facing']}
- **Sensitive Data**: {context_summary['sensitive_data']}
- **Data Classification**: {context_summary['data_classification']}
- **Deployment**: {context_summary['deployment']}
- **Compliance**: {context_summary['compliance']}

## Executive Summary
- **Total Threats Identified**: {executive_summary.get('total_threats', len(threats))}
- **Critical Threats**: {executive_summary.get('critical_threats', 0)}
- **High Risk Areas**: {', '.join(executive_summary.get('high_risk_areas', []))}

### Top Recommendations
"""
    
    for i, rec in enumerate(executive_summary.get('top_recommendations', []), 1):
        md_content += f"{i}. {rec}\n"
    
    md_content += "\n## Detailed Threat Analysis\n\n"
    
    # Group threats by STRIDE category
    stride_categories = {}
    for threat in threats:
        category = threat.get('threat_type', 'Unknown')
        if category not in stride_categories:
            stride_categories[category] = []
        stride_categories[category].append(threat)
    
    for category, category_threats in stride_categories.items():
        md_content += f"### {category}\n\n"
        
        for i, threat in enumerate(category_threats, 1):
            md_content += f"#### {category} Threat #{i}\n"
            md_content += f"**Scenario**: {threat.get('scenario', 'N/A')}\n\n"
            md_content += f"**Attack Vector**: {threat.get('attack_vector', 'N/A')}\n\n"
            md_content += f"**Impact**: {threat.get('potential_impact', 'N/A')}\n\n"
            md_content += f"**Likelihood**: {threat.get('likelihood', 'N/A')}\n\n"
            md_content += f"**Affected Components**: {', '.join(threat.get('affected_components', []))}\n\n"
            md_content += f"**Priority**: {threat.get('mitigation_priority', 'N/A')}\n\n"
            md_content += "---\n\n"
    
    # Add improvement suggestions
    improvements = threat_data.get('improvement_suggestions', [])
    if improvements:
        md_content += "## Improvement Suggestions\n\n"
        for i, suggestion in enumerate(improvements, 1):
            md_content += f"{i}. {suggestion}\n"
    
    return md_content


def _generate_csv_report(threat_data):
    """Generate a CSV report from threat model data."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        'Threat Type', 'Scenario', 'Attack Vector', 'Impact', 'Likelihood', 
        'Affected Components', 'Priority'
    ])
    
    # Data rows
    for threat in threat_data.get('threat_model', []):
        writer.writerow([
            threat.get('threat_type', ''),
            threat.get('scenario', ''),
            threat.get('attack_vector', ''),
            threat.get('potential_impact', ''),
            threat.get('likelihood', ''),
            ', '.join(threat.get('affected_components', [])),
            threat.get('mitigation_priority', '')
        ])
    
    return output.getvalue()


def validate_threat_model_completeness(threat_model_id):
    """
    Validate that a threat model covers all STRIDE categories adequately.
    
    Args:
        threat_model_id (int): ThreatModel database ID
        
    Returns:
        dict: Validation results and recommendations
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
        threat_data = tm_obj.threat_model_data
        
        if not threat_data:
            return {'valid': False, 'message': 'No threat model data found'}
        
        threats = threat_data.get('threat_model', [])
        stride_categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']
        
        validation = {
            'valid': True,
            'coverage': {},
            'missing_categories': [],
            'recommendations': [],
            'total_threats': len(threats)
        }
        
        # Check STRIDE coverage
        threat_types = [threat.get('threat_type', '').lower() for threat in threats]
        
        for category in stride_categories:
            category_lower = category.lower()
            count = sum(1 for tt in threat_types if category_lower in tt.lower())
            validation['coverage'][category] = count
            
            if count == 0:
                validation['missing_categories'].append(category)
                validation['valid'] = False
            elif count < 2:
                validation['recommendations'].append(f"Consider adding more {category} threats for comprehensive coverage")
        
        # Check threat detail completeness
        required_fields = ['scenario', 'attack_vector', 'potential_impact', 'likelihood']
        incomplete_threats = []
        
        for i, threat in enumerate(threats):
            missing_fields = [field for field in required_fields if not threat.get(field)]
            if missing_fields:
                incomplete_threats.append({'threat_index': i, 'missing_fields': missing_fields})
        
        if incomplete_threats:
            validation['incomplete_threats'] = incomplete_threats
            validation['recommendations'].append("Some threats are missing required details (scenario, attack_vector, impact, likelihood)")
        
        # Overall quality assessment
        if validation['total_threats'] < 12:  # Minimum 2 per STRIDE category
            validation['recommendations'].append("Consider adding more threats for comprehensive coverage (minimum 12 total)")
        
        return validation
        
    except ThreatModel.DoesNotExist:
        return {'valid': False, 'message': f'ThreatModel ID {threat_model_id} not found'}
    
def create_correlation_prompt(original_threat_model, new_context):
    """Creates a prompt for the AI to perform a re-validation analysis."""
    return f"""
Act as a cyber security expert performing a re-validation of a threat model.
Below is the original threat model report and context retrieved from the application's NEW documentation.

Your task is to analyze the new context and determine the current status of each original threat.
Produce a JSON object with three lists: 'mitigated_threats', 'persistent_threats', and 'new_threats'.

- A threat is MITIGATED if the new documentation provides clear evidence that a specific control has been implemented to address it.
- A threat is PERSISTENT if there is no evidence of mitigation in the new documentation.
- A NEW THREAT is a risk that is evident from the new documentation but was not present in the original model.

ORIGINAL THREAT MODEL:
{json.dumps(original_threat_model, indent=2)}

CONTEXT FROM NEW DOCUMENTATION:
{new_context}

Output your analysis in the following valid JSON structure:
{{
  "mitigated_threats": [{{ "threat_id": "...", "justification": "..." }}],
  "persistent_threats": [{{ "threat_id": "...", "justification": "..." }}],
  "new_threats": [{{ "threat_type": "...", "scenario": "...", "etc...": "..." }}]
}}
"""

def generate_correlation_report(threat_model_id, api_key, model_name="gpt-4.1"):
    """
    Generates a correlation report by comparing the last analysis with new documentation.
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
        original_report = tm_obj.threat_model_data
        if not original_report:
            raise ValueError("No original threat model found to correlate against.")
    except ThreatModel.DoesNotExist:
        raise ValueError(f"ThreatModel ID {threat_model_id} not found.")

    # Retrieve context from the NEW (latest) FAISS index
    query = f"Review of security posture for {tm_obj.app_name} based on previous threats."
    new_chunks = search_faiss(threat_model_id, query, top_k=20)
    new_context = "\\n\\n--- DOCUMENT SECTION ---\\n".join([
        f"File: {chunk['filename']}\\n{chunk.get('chunk_text', '')}"
        for chunk in new_chunks
    ])

    # Build the prompts
    prompt = create_correlation_prompt(original_report, new_context)
    system_prompt = "You are a security analyst. Your task is to perform a differential threat analysis based on the provided data and return the result in valid JSON."

    # Call the LLM
    correlation_json = generate_json_response(
        provider="openai",
        api_key=api_key,
        model_name=model_name,
        system_prompt=system_prompt,
        user_prompt=prompt
    )

    # You would then add logic here to parse the correlation_json and update
    # the original threat model's status or generate a new report.

    return correlation_json
def _generate_csv_report(threat_data):
    """Generate a CSV report with Threat ID, Mitigation Suggestion, and Status columns."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Updated headers with the more useful columns
    writer.writerow([
        'Threat ID', 'Threat Type', 'Scenario', 'Attack Vector', 'Impact (Severity)', 'Likelihood', 
        'Affected Components', 'Mitigation Suggestion', 'Status'
    ])
    
    for threat in threat_data.get('threat_model', []):
        writer.writerow([
            threat.get('threat_id', ''),
            threat.get('threat_type', ''),
            threat.get('scenario', ''),
            threat.get('attack_vector', ''),
            threat.get('potential_impact', ''),
            threat.get('likelihood', ''),
            ', '.join(threat.get('affected_components', [])),
            threat.get('mitigation_suggestion', ''),  
            threat.get('status', 'Open')
        ])
    
    return output.getvalue()
def create_correlation_prompt(original_threat_model, new_context):
    """Creates a prompt for the AI to perform a re-validation analysis."""
    return f"""
    Act as a cyber security expert performing a re-validation of a threat model.
    Below is the original threat model report and context retrieved from the application's NEW documentation.

    Your task is to analyze the new context and determine the current status of each original threat.
    Produce a JSON object with three lists: 'mitigated_threats', 'persistent_threats', and 'new_threats'.

    - A threat is MITIGATED if the new documentation provides clear evidence that a specific control has been implemented to address it.
    - A threat is PERSISTENT if there is no evidence of mitigation in the new documentation.
    - A NEW THREAT is a risk that is evident from the new documentation but was not present in the original model.

    ORIGINAL THREAT MODEL:
    {json.dumps(original_threat_model, indent=2)}

    CONTEXT FROM NEW DOCUMENTATION:
    {new_context}

    Output your analysis in the following valid JSON structure:
    {{
    "mitigated_threats": [{{ "threat_id": "...", "justification": "..." }}],
    "persistent_threats": [{{ "threat_id": "...", "justification": "..." }}],
    "new_threats": [{{ "threat_id": "...", "threat_type": "...", "scenario": "...", "etc...": "..." }}]
    }}
    """

def generate_correlation_report(threat_model_id, api_key, model_name="gpt-4.1"):
    """
    Generates a correlation report by comparing the last analysis with new documentation.
    """
    try:
        tm_obj = ThreatModel.objects.get(id=threat_model_id)
        original_report = tm_obj.threat_model_data
        if not original_report or 'threat_model' not in original_report:
            raise ValueError("No original threat model found to correlate against.")
    except ThreatModel.DoesNotExist:
        raise ValueError(f"ThreatModel ID {threat_model_id} not found.")

    query = f"Review of security posture for {tm_obj.app_name} based on previous threats."
    new_chunks = search_faiss(threat_model_id, query, top_k=20)
    new_context = "\\n\\n--- DOCUMENT SECTION ---\\n".join([
        f"File: {chunk['filename']}\\n{chunk.get('chunk_text', '')}"
        for chunk in new_chunks
    ])

    prompt = create_correlation_prompt(original_report, new_context)
    system_prompt = "You are a security analyst. Your task is to perform a differential threat analysis and return the result in valid JSON."

    correlation_json = generate_json_response(
        provider="openai",
        api_key=api_key,
        model_name=model_name,
        system_prompt=system_prompt,
        user_prompt=prompt
    )
    
    
    updated_threat_model = json.loads(json.dumps(original_report))
    original_threats_map = {threat.get('threat_id'): threat for threat in updated_threat_model.get('threat_model', [])}

    for mitigated in correlation_json.get('mitigated_threats', []):
        threat_id = mitigated.get('threat_id')
        if threat_id in original_threats_map:
            original_threats_map[threat_id]['status'] = 'Mitigated'
            original_threats_map[threat_id]['mitigation_justification'] = mitigated.get('justification')

    for persistent in correlation_json.get('persistent_threats', []):
        threat_id = persistent.get('threat_id')
        if threat_id in original_threats_map:
            original_threats_map[threat_id]['status'] = 'Persistent (Unmitigated)'
            original_threats_map[threat_id]['mitigation_justification'] = persistent.get('justification')

    new_threats_list = updated_threat_model.get('threat_model', [])
    for new_threat in correlation_json.get('new_threats', []):
        new_threat['status'] = 'Open'
        new_threats_list.append(new_threat)
    
    updated_threat_model['threat_model'] = new_threats_list

    tm_obj.threat_model_data = updated_threat_model
    tm_obj.last_analysis_at = datetime.now(timezone.utc)
    tm_obj.save()

    return updated_threat_model




