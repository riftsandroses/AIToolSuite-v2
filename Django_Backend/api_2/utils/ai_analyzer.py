"""
AI-powered vulnerability analysis utility using OpenAI GPT models
"""
import openai
import json
import logging
from typing import Dict, List, Any, Optional
from django.conf import settings

logger = logging.getLogger(__name__)


class VulnerabilityAnalyzerTC2:
    """AI-powered vulnerability analyzer using OpenAI"""
    
    def __init__(self):
        self.client = openai.OpenAI(
            api_key=getattr(settings, 'OPENAI_API_KEY', '')
        )
        self.model = "gpt-4o-mini"
    
    def analyze_credential_stuffing_results(self, 
                                          test_results: Dict[str, Any], 
                                          api_info: Dict[str, str]) -> Dict[str, Any]:
        """Analyze credential stuffing test results using AI"""
        
        if not self.client.api_key:
            return self._fallback_analysis(test_results, api_info)
        
        try:
            prompt = self._build_analysis_prompt(test_results, api_info)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=1500,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            analysis = json.loads(response.choices[0].message.content)
            return self._validate_analysis(analysis)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            return self._fallback_analysis(test_results, api_info)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(test_results, api_info)
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for vulnerability analysis"""
        return """
        You are a cybersecurity expert specializing in API vulnerability assessment.
        Your task is to analyze credential stuffing/brute force attack test results and provide:
        
        1. Accurate vulnerability severity assessment
        2. Technical exploitation analysis
        3. Detailed security findings
        4. Practical remediation recommendations
        5. Risk scoring based on OWASP standards
        
        Always respond with valid JSON containing the required fields.
        Base your analysis on actual test results and evidence.
        """
    
    def _build_analysis_prompt(self, test_results: Dict[str, Any], api_info: Dict[str, str]) -> str:
        """Build analysis prompt from test results"""
        
        avg_response_time = (
            sum(test_results.get('response_times', [])) / 
            len(test_results.get('response_times', [1]))
        ) if test_results.get('response_times') else 0
        
        return f"""
        Analyze the following credential stuffing vulnerability test results:
        
        API Information:
        - Name: {api_info.get('name', 'Unknown')}
        - URL: {api_info.get('url', 'Unknown')}
        - Method: {api_info.get('method', 'Unknown')}
        
        Test Results:
        - Total login attempts: {test_results.get('total_attempts', 0)}
        - Successful logins: {test_results.get('successful_attempts', 0)}
        - Failed attempts: {test_results.get('failed_attempts', 0)}
        - Rate limited attempts: {test_results.get('rate_limited_attempts', 0)}
        - Average response time: {avg_response_time:.2f}s
        - HTTP status codes observed: {test_results.get('status_codes', {})}
        
        Security Controls Detected:
        - Rate limiting: {'Yes' if test_results.get('rate_limiting_detected') else 'No'}
        - Account lockout: {'Yes' if test_results.get('account_lockout_detected') else 'No'}
        - CAPTCHA protection: {'Yes' if test_results.get('captcha_detected') else 'No'}
        
        Sample Response Analysis:
        {json.dumps(test_results.get('responses', [])[:3], indent=2)}
        
        Provide analysis in JSON format with these exact fields:
        {{
            "severity": "low|medium|high|critical",
            "exploit_successful": true/false,
            "vulnerability_confirmed": true/false,
            "findings": "Detailed technical findings",
            "security_controls_bypassed": ["list", "of", "bypassed", "controls"],
            "attack_vectors": ["possible", "attack", "methods"],
            "recommendations": ["specific", "remediation", "steps"],
            "risk_score": 0-10,
            "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "technical_details": {{
                "authentication_bypass": true/false,
                "credential_validation_weak": true/false,
                "rate_limiting_effective": true/false,
                "response_time_analysis": "consistent/inconsistent/suspicious"
            }},
            "evidence": {{
                "successful_credentials": ["found", "working", "creds"],
                "response_patterns": "description of patterns",
                "timing_attack_possible": true/false
            }}
        }}
        """
    
    def _validate_analysis(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and clean AI analysis response"""
        
        # Ensure required fields exist
        required_fields = [
            'severity', 'exploit_successful', 'vulnerability_confirmed',
            'findings', 'recommendations', 'risk_score'
        ]
        
        for field in required_fields:
            if field not in analysis:
                if field == 'severity':
                    analysis[field] = 'low'
                elif field in ['exploit_successful', 'vulnerability_confirmed']:
                    analysis[field] = False
                elif field in ['findings', 'recommendations']:
                    analysis[field] = 'Analysis incomplete'
                elif field == 'risk_score':
                    analysis[field] = 1
        
        # Validate severity values
        valid_severities = ['low', 'medium', 'high', 'critical']
        if analysis.get('severity') not in valid_severities:
            analysis['severity'] = 'low'
        
        # Ensure risk_score is within bounds
        try:
            risk_score = float(analysis.get('risk_score', 1))
            analysis['risk_score'] = max(0, min(10, risk_score))
        except (ValueError, TypeError):
            analysis['risk_score'] = 1
        
        # Ensure boolean fields are boolean
        for field in ['exploit_successful', 'vulnerability_confirmed']:
            if not isinstance(analysis.get(field), bool):
                analysis[field] = False
        
        # Ensure list fields are lists
        for field in ['recommendations', 'security_controls_bypassed', 'attack_vectors']:
            if field in analysis and not isinstance(analysis[field], list):
                if isinstance(analysis[field], str):
                    analysis[field] = [analysis[field]]
                else:
                    analysis[field] = []
        
        return analysis
    
    def _fallback_analysis(self, test_results: Dict[str, Any], api_info: Dict[str, str]) -> Dict[str, Any]:
        """Fallback analysis when AI is not available"""
        
        total_attempts = test_results.get('total_attempts', 0)
        successful_attempts = test_results.get('successful_attempts', 0)
        rate_limiting = test_results.get('rate_limiting_detected', False)
        account_lockout = test_results.get('account_lockout_detected', False)
        captcha = test_results.get('captcha_detected', False)
        
        # Determine vulnerability
        vulnerability_confirmed = False
        severity = 'low'
        risk_score = 1
        
        # Check for successful exploitation
        exploit_successful = successful_attempts > 0
        if exploit_successful:
            vulnerability_confirmed = True
            severity = 'critical'
            risk_score = 10
        
        # Check for missing security controls
        elif total_attempts > 20 and not rate_limiting:
            vulnerability_confirmed = True
            if not account_lockout and not captcha:
                severity = 'high'
                risk_score = 8
            else:
                severity = 'medium'
                risk_score = 6
        
        elif total_attempts > 10 and not (rate_limiting and account_lockout):
            vulnerability_confirmed = True
            severity = 'medium'
            risk_score = 5
        
        # Build findings
        findings = f"Tested {total_attempts} credential combinations against {api_info.get('name', 'API')}. "
        
        if exploit_successful:
            findings += f"Successfully authenticated with {successful_attempts} credential(s). "
        
        if not rate_limiting:
            findings += "No rate limiting detected on authentication endpoint. "
        
        if not account_lockout:
            findings += "No account lockout mechanism implemented. "
        
        if not captcha:
            findings += "No CAPTCHA protection observed. "
        
        # Build recommendations
        recommendations = []
        if not rate_limiting:
            recommendations.append("Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute per IP)")
        
        if not account_lockout:
            recommendations.append("Implement account lockout after consecutive failed attempts")
        
        if not captcha:
            recommendations.append("Consider implementing CAPTCHA after multiple failed attempts")
        
        if exploit_successful:
            recommendations.append("URGENT: Change all default credentials immediately")
            recommendations.append("Implement strong password policy")
            recommendations.append("Enable multi-factor authentication (MFA)")
        
        if vulnerability_confirmed:
            recommendations.append("Monitor authentication logs for suspicious activity")
            recommendations.append("Implement account monitoring and alerting")
        
        # Security controls assessment
        security_controls_bypassed = []
        if not rate_limiting:
            security_controls_bypassed.append("rate_limiting")
        if not account_lockout:
            security_controls_bypassed.append("account_lockout")
        if not captcha:
            security_controls_bypassed.append("captcha_protection")
        
        # Attack vectors
        attack_vectors = ["credential_stuffing", "brute_force"]
        if exploit_successful:
            attack_vectors.extend(["default_credentials", "weak_passwords"])
        
        # Generate CVSS score
        cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        if severity == 'critical':
            cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        elif severity == 'high':
            cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        elif severity == 'medium':
            cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        
        return {
            'severity': severity,
            'exploit_successful': exploit_successful,
            'vulnerability_confirmed': vulnerability_confirmed,
            'findings': findings.strip(),
            'security_controls_bypassed': security_controls_bypassed,
            'attack_vectors': attack_vectors,
            'recommendations': recommendations,
            'risk_score': risk_score,
            'cvss_score': cvss_score,
            'technical_details': {
                'authentication_bypass': exploit_successful,
                'credential_validation_weak': exploit_successful,
                'rate_limiting_effective': rate_limiting,
                'response_time_analysis': 'consistent'
            },
            'evidence': {
                'successful_credentials': [] if not exploit_successful else ['found_valid_credentials'],
                'response_patterns': 'Standard HTTP responses observed',
                'timing_attack_possible': False
            }
        }
    
    def generate_security_report(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive security report using AI"""
        
        if not self.client.api_key:
            return self._generate_basic_report(scan_results)
        
        try:
            # Summarize findings
            total_apis = len(scan_results)
            vulnerable_apis = len([r for r in scan_results if r.get('vulnerability_found')])
            critical_vulns = len([r for r in scan_results if r.get('severity') == 'critical'])
            high_vulns = len([r for r in scan_results if r.get('severity') == 'high'])
            
            prompt = f"""
            Generate a comprehensive security assessment report based on the following vulnerability scan results:
            
            Scan Summary:
            - Total APIs tested: {total_apis}
            - Vulnerable APIs found: {vulnerable_apis}
            - Critical vulnerabilities: {critical_vulns}
            - High-severity vulnerabilities: {high_vulns}
            
            Detailed Results:
            {json.dumps(scan_results[:10], indent=2)}  # Limit for token constraints
            
            Provide a JSON report with:
            {{
                "executive_summary": "Brief overview for executives",
                "technical_summary": "Detailed technical findings",
                "risk_assessment": "Overall risk level and impact",
                "priority_actions": ["immediate", "actions", "required"],
                "compliance_impact": "Impact on compliance/regulations",
                "business_impact": "Potential business consequences",
                "remediation_timeline": "Suggested timeline for fixes",
                "overall_security_posture": "poor|fair|good|excellent"
            }}
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior cybersecurity consultant creating executive security reports."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=1000,
                temperature=0.2,
                response_format={"type": "json_object"}
            )
            
            report = json.loads(response.choices[0].message.content)
            return report
            
        except Exception as e:
            logger.error(f"AI report generation failed: {e}")
            return self._generate_basic_report(scan_results)
    
    def _generate_basic_report(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate basic report without AI"""
        
        total_apis = len(scan_results)
        vulnerable_apis = len([r for r in scan_results if r.get('vulnerability_found')])
        critical_vulns = len([r for r in scan_results if r.get('severity') == 'critical'])
        high_vulns = len([r for r in scan_results if r.get('severity') == 'high'])
        
        # Determine overall security posture
        if critical_vulns > 0:
            posture = "poor"
        elif high_vulns > total_apis * 0.3:
            posture = "fair" 
        elif vulnerable_apis < total_apis * 0.1:
            posture = "good"
        else:
            posture = "fair"
        
        return {
            "executive_summary": f"Security assessment of {total_apis} APIs identified {vulnerable_apis} vulnerable endpoints, including {critical_vulns} critical and {high_vulns} high-severity issues requiring immediate attention.",
            "technical_summary": f"Credential stuffing vulnerability assessment revealed weak authentication controls across {vulnerable_apis} of {total_apis} tested APIs. Primary issues include missing rate limiting, weak credential validation, and lack of account lockout mechanisms.",
            "risk_assessment": "High" if critical_vulns > 0 else "Medium" if high_vulns > 0 else "Low",
            "priority_actions": [
                "Implement rate limiting on all authentication endpoints",
                "Enable account lockout after failed attempts", 
                "Change default credentials immediately",
                "Deploy multi-factor authentication"
            ] if vulnerable_apis > 0 else ["Continue monitoring and regular assessments"],
            "compliance_impact": "Identified vulnerabilities may violate PCI-DSS, SOX, and GDPR requirements for data protection and access controls.",
            "business_impact": "Critical vulnerabilities pose immediate risk of data breach, unauthorized access, and potential regulatory penalties.",
            "remediation_timeline": "Critical issues: 24-48 hours, High severity: 1 week, Medium/Low: 1 month",
            "overall_security_posture": posture
        }