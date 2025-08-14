import openai
import json
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class AIAnalyzerTC2:
    """AI-powered security analysis using OpenAI GPT models"""
    
    def __init__(self):
        self.client = openai.OpenAI(api_key=getattr(settings, 'OPENAI_API_KEY', ''))
        self.model = "gpt-4o-mini"
    
    def analyze_tls_security(self, analysis_data):
        """
        Analyze TLS/Transport security findings using AI
        
        Args:
            analysis_data (dict): Contains API info, TLS findings, headers, etc.
            
        Returns:
            dict: AI analysis results with recommendations and confidence scores
        """
        try:
            if not self.client.api_key:
                logger.warning("OpenAI API key not configured, using fallback analysis")
                return self._fallback_analysis(analysis_data)
            
            prompt = self._build_security_analysis_prompt(analysis_data)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_security_expert_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            analysis_result = self._parse_ai_response(response.choices[0].message.content)
            return analysis_result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return self._fallback_analysis(analysis_data)
    
    def _get_security_expert_system_prompt(self):
        """System prompt for security expert AI"""
        return """You are an expert cybersecurity analyst specializing in API security, TLS/SSL configuration, and transport security. 

Your role is to:
1. Analyze TLS/transport security findings for web APIs
2. Assess severity and exploitability of security issues
3. Provide detailed technical analysis and remediation recommendations
4. Score confidence levels for your assessments

Focus on:
- TLS protocol versions and cipher suites
- Certificate validation and trust chains
- HTTP vs HTTPS availability and redirects
- Security headers (HSTS, CSP, X-Content-Type-Options, etc.)
- SSL stripping and downgrade attack vectors
- Man-in-the-middle attack possibilities

Provide responses in JSON format with structured analysis."""
    
    def _build_security_analysis_prompt(self, data):
        """Build the analysis prompt from security findings"""
        prompt = f"""
Analyze the following API security findings:

API Information:
- Name: {data.get('api_name', 'Unknown')}
- URL: {data.get('url', 'Unknown')}
- Method: {data.get('method', 'Unknown')}

Security Findings:
- HTTP Available: {data.get('http_available', False)}
- HTTPS Available: {data.get('https_available', False)}
- TLS Information: {json.dumps(data.get('tls_info', {}), indent=2)}
- Security Headers: {json.dumps(data.get('security_headers', {}), indent=2)}

Please provide a comprehensive security analysis including:

1. HTTP Analysis: Risk assessment if HTTP is available
2. TLS Analysis: Assessment of TLS configuration weaknesses
3. HSTS Analysis: Impact of missing or weak HSTS implementation  
4. Security Headers Analysis: Risk of missing security headers
5. Overall Risk Assessment: Combined risk score and priority
6. Exploitation Scenarios: Realistic attack vectors
7. Remediation Recommendations: Specific technical fixes

Format your response as JSON with the following structure:
{{
    "http_analysis": "detailed analysis text",
    "tls_analysis": "detailed analysis text", 
    "hsts_analysis": "detailed analysis text",
    "headers_analysis": "detailed analysis text",
    "overall_risk": "low|medium|high|critical",
    "exploitation_scenarios": ["scenario1", "scenario2"],
    "remediation_recommendations": ["rec1", "rec2"],
    "confidence_scores": {{
        "http": 0.0-1.0,
        "tls": 0.0-1.0,
        "hsts": 0.0-1.0,
        "headers": 0.0-1.0,
        "overall": 0.0-1.0
    }},
    "technical_details": "additional technical context"
}}
"""
        return prompt
    
    def _parse_ai_response(self, response_text):
        """Parse AI response and extract structured analysis"""
        try:
            # Try to extract JSON from the response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            
            if start != -1 and end != 0:
                json_text = response_text[start:end]
                return json.loads(json_text)
            else:
                # Fallback parsing
                return {
                    "http_analysis": response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    "tls_analysis": "",
                    "hsts_analysis": "",
                    "headers_analysis": "",
                    "overall_risk": "medium",
                    "exploitation_scenarios": [],
                    "remediation_recommendations": [],
                    "confidence_scores": {
                        "http": 0.5,
                        "tls": 0.5,
                        "hsts": 0.5,
                        "headers": 0.5,
                        "overall": 0.5
                    },
                    "technical_details": response_text
                }
        except json.JSONDecodeError:
            logger.error(f"Failed to parse AI response as JSON: {response_text[:100]}...")
            return self._fallback_analysis({})
    
    def _fallback_analysis(self, analysis_data):
        """Provide basic rule-based analysis when AI is unavailable"""
        http_available = analysis_data.get('http_available', False)
        https_available = analysis_data.get('https_available', False)
        tls_info = analysis_data.get('tls_info', {})
        security_headers = analysis_data.get('security_headers', {})
        
        analysis = {
            "http_analysis": "",
            "tls_analysis": "",
            "hsts_analysis": "",
            "headers_analysis": "",
            "overall_risk": "low",
            "exploitation_scenarios": [],
            "remediation_recommendations": [],
            "confidence_scores": {
                "http": 0.8,
                "tls": 0.7,
                "hsts": 0.7,
                "headers": 0.6,
                "overall": 0.7
            },
            "technical_details": "Rule-based analysis (AI unavailable)"
        }
        
        # HTTP Analysis
        if http_available:
            analysis["http_analysis"] = "API is accessible over HTTP, allowing potential eavesdropping and man-in-the-middle attacks."
            analysis["overall_risk"] = "high"
            analysis["exploitation_scenarios"].append("SSL stripping attack")
            analysis["remediation_recommendations"].append("Disable HTTP access or implement HTTPS redirect")
        
        # TLS Analysis
        if tls_info.get('weak_protocols'):
            analysis["tls_analysis"] = f"Weak TLS protocols detected: {tls_info.get('weak_protocols')}. Vulnerable to downgrade attacks."
            if analysis["overall_risk"] == "low":
                analysis["overall_risk"] = "medium"
            analysis["exploitation_scenarios"].append("TLS downgrade attack")
            analysis["remediation_recommendations"].append("Disable TLS 1.0/1.1, use only TLS 1.2+")
        
        # HSTS Analysis
        if not security_headers.get('hsts') and https_available:
            analysis["hsts_analysis"] = "Missing HSTS header allows SSL stripping attacks in mixed content scenarios."
            analysis["remediation_recommendations"].append("Implement Strict-Transport-Security header")
        
        # Headers Analysis
        missing_headers = security_headers.get('missing_headers', [])
        if missing_headers:
            analysis["headers_analysis"] = f"Missing security headers: {', '.join(missing_headers)}. May allow content sniffing and XSS attacks."
            analysis["remediation_recommendations"].append("Implement missing security headers")
        
        return analysis
    
    def analyze_vulnerability_impact(self, vulnerability_data):
        """Analyze the business impact of a vulnerability"""
        try:
            if not self.client.api_key:
                return self._fallback_impact_analysis(vulnerability_data)
            
            prompt = f"""
Analyze the business impact of this security vulnerability:

Vulnerability: {vulnerability_data.get('title', 'Unknown')}
Description: {vulnerability_data.get('description', 'Unknown')}
Severity: {vulnerability_data.get('severity', 'Unknown')}
API: {vulnerability_data.get('api_name', 'Unknown')} - {vulnerability_data.get('api_url', 'Unknown')}

Provide analysis of:
1. Potential business impact
2. Data exposure risks
3. Compliance implications
4. Likelihood of exploitation
5. Recommended timeline for remediation

Format as JSON with impact_score (0-10), business_impact, compliance_risks, and remediation_timeline.
"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity risk analyst specializing in business impact assessment."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            return self._parse_ai_response(response.choices[0].message.content)
            
        except Exception as e:
            logger.error(f"Impact analysis failed: {str(e)}")
            return self._fallback_impact_analysis(vulnerability_data)
    
    def _fallback_impact_analysis(self, vulnerability_data):
        """Fallback impact analysis when AI is unavailable"""
        severity = vulnerability_data.get('severity', 'low')
        
        impact_scores = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        
        timelines = {
            'critical': '24 hours',
            'high': '1 week',
            'medium': '1 month',
            'low': '3 months',
            'info': '6 months'
        }
        
        return {
            'impact_score': impact_scores.get(severity, 5),
            'business_impact': f"Potential {severity} level security risk affecting API transport security",
            'compliance_risks': "May violate security compliance requirements for data in transit",
            'remediation_timeline': timelines.get(severity, '1 month'),
            'confidence_score': 0.7
        }