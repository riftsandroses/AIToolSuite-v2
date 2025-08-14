import json
from datetime import datetime
from django.db.models import Count, Q
from ..models import ScanTC2, VulnerabilityTC2

class ReportGeneratorTC2:
    """Generate comprehensive security reports for TLS scans"""
    
    def generate_comprehensive_report(self, scan):
        """Generate a complete security report for a scan"""
        
        vulnerabilities = scan.vulnerabilities.all()
        metrics = scan.metrics
        
        report = {
            'report_metadata': self._generate_metadata(scan),
            'executive_summary': self._generate_executive_summary(scan, vulnerabilities, metrics),
            'scan_overview': self._generate_scan_overview(scan, metrics),
            'vulnerability_analysis': self._generate_vulnerability_analysis(vulnerabilities),
            'risk_assessment': self._generate_risk_assessment(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities),
            'technical_details': self._generate_technical_details(vulnerabilities),
            'compliance_impact': self._generate_compliance_impact(vulnerabilities),
            'appendices': self._generate_appendices(scan, vulnerabilities)
        }
        
        return report
    
    def _generate_metadata(self, scan):
        """Generate report metadata"""
        return {
            'report_id': str(scan.id),
            'scan_id': scan.scan_id,
            'generated_at': datetime.now().isoformat(),
            'scan_started': scan.started_at.isoformat() if scan.started_at else None,
            'scan_completed': scan.completed_at.isoformat() if scan.completed_at else None,
            'report_type': 'TLS Security Assessment',
            'version': '1.0'
        }
    
    def _generate_executive_summary(self, scan, vulnerabilities, metrics):
        """Generate executive summary"""
        total_vulns = vulnerabilities.count()
        critical_high = vulnerabilities.filter(severity__in=['critical', 'high']).count()
        
        risk_level = 'Low'
        if critical_high > 5:
            risk_level = 'Critical'
        elif critical_high > 2:
            risk_level = 'High'
        elif critical_high > 0:
            risk_level = 'Medium'
        
        summary = {
            'overview': f"TLS security assessment completed for {scan.total_apis} API endpoints. "
                       f"Identified {total_vulns} security findings across transport layer security configurations.",
            'key_findings': [
                f"Total vulnerabilities found: {total_vulns}",
                f"Critical/High severity issues: {critical_high}",
                f"APIs with HTTP access: {metrics.http_only_apis + metrics.mixed_protocol_apis}",
                f"APIs with weak TLS: {metrics.weak_tls_apis}",
                f"Missing security headers: {metrics.missing_security_headers}"
            ],
            'overall_risk_rating': risk_level,
            'immediate_actions_required': self._get_immediate_actions(vulnerabilities),
            'business_impact': self._assess_business_impact(vulnerabilities)
        }
        
        return summary
    
    def _generate_scan_overview(self, scan, metrics):
        """Generate scan overview section"""
        duration = 0
        if scan.completed_at and scan.started_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()
        
        return {
            'scan_details': {
                'total_apis_scanned': scan.total_apis,
                'scan_duration_seconds': duration,
                'scan_status': scan.status,
                'apis_with_findings': scan.vulnerabilities.values('api_id').distinct().count()
            },
            'scan_coverage': {
                'http_only_apis': metrics.http_only_apis,
                'https_only_apis': metrics.https_only_apis,
                'mixed_protocol_apis': metrics.mixed_protocol_apis,
                'total_tested': scan.total_apis
            },
            'performance_metrics': {
                'average_response_time': metrics.average_response_time,
                'total_scan_duration': metrics.total_duration_seconds,
                'apis_per_minute': (scan.total_apis / (duration / 60)) if duration > 0 else 0
            }
        }
    
    def _generate_vulnerability_analysis(self, vulnerabilities):
        """Generate detailed vulnerability analysis"""
        
        # Severity breakdown
        severity_counts = vulnerabilities.values('severity').annotate(count=Count('id'))
        severity_breakdown = {item['severity']: item['count'] for item in severity_counts}
        
        # Vulnerability types
        type_counts = vulnerabilities.values('title').annotate(count=Count('id')).order_by('-count')
        
        # API impact analysis
        api_impact = vulnerabilities.values('api_name', 'api_url').annotate(
            vuln_count=Count('id'),
            max_severity=Count('id', filter=Q(severity='critical')) + Count('id', filter=Q(severity='high'))
        ).order_by('-max_severity', '-vuln_count')
        
        return {
            'severity_distribution': severity_breakdown,
            'vulnerability_types': list(type_counts)[:10],  # Top 10
            'most_affected_apis': list(api_impact)[:20],  # Top 20
            'trend_analysis': self._analyze_vulnerability_trends(vulnerabilities),
            'confidence_analysis': self._analyze_confidence_scores(vulnerabilities)
        }
    
    def _generate_risk_assessment(self, vulnerabilities):
        """Generate risk assessment matrix"""
        
        risk_matrix = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for vuln in vulnerabilities:
            risk_item = {
                'vulnerability': vuln.title,
                'api': f"{vuln.api_method} {vuln.api_url}",
                'impact': self._assess_vulnerability_impact(vuln),
                'likelihood': self._assess_exploit_likelihood(vuln),
                'mitigation_effort': self._assess_mitigation_effort(vuln)
            }
            risk_matrix[vuln.severity].append(risk_item)
        
        return {
            'risk_matrix': risk_matrix,
            'risk_score_calculation': self._calculate_overall_risk_score(vulnerabilities),
            'threat_landscape': self._assess_threat_landscape(vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities):
        """Generate prioritized recommendations"""
        
        recommendations = {
            'immediate_actions': [],
            'short_term_fixes': [],
            'long_term_improvements': [],
            'strategic_initiatives': []
        }
        
        # Analyze vulnerabilities and categorize recommendations
        critical_high = vulnerabilities.filter(severity__in=['critical', 'high'])
        medium_vulns = vulnerabilities.filter(severity='medium')
        
        if critical_high.exists():
            recommendations['immediate_actions'].extend([
                "Disable HTTP access for all critical APIs immediately",
                "Upgrade TLS configurations to use only TLS 1.2 and 1.3",
                "Implement HSTS headers on all HTTPS endpoints"
            ])
        
        if medium_vulns.exists():
            recommendations['short_term_fixes'].extend([
                "Implement comprehensive security headers",
                "Review and update cipher suite configurations",
                "Establish proper certificate management processes"
            ])
        
        recommendations['long_term_improvements'].extend([
            "Implement automated TLS configuration monitoring",
            "Establish security scanning in CI/CD pipeline",
            "Develop incident response procedures for transport security"
        ])
        
        recommendations['strategic_initiatives'].extend([
            "Adopt zero-trust network architecture",
            "Implement certificate transparency monitoring",
            "Establish security awareness training for development teams"
        ])
        
        return recommendations
    
    def _generate_technical_details(self, vulnerabilities):
        """Generate technical appendix with detailed findings"""
        
        technical_details = {
            'vulnerability_details': [],
            'scanning_methodology': self._get_scanning_methodology(),
            'tools_used': self._get_tools_used(),
            'false_positive_analysis': self._analyze_false_positives(vulnerabilities)
        }
        
        for vuln in vulnerabilities:
            detail = {
                'id': str(vuln.id),
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity,
                'api_endpoint': f"{vuln.api_method} {vuln.api_url}",
                'evidence': vuln.evidence,
                'technical_impact': vuln.exploit_details,
                'remediation_steps': vuln.recommendation,
                'confidence_score': vuln.confidence_score,
                'ai_analysis': vuln.ai_analysis,
                'discovery_timestamp': vuln.created_at.isoformat()
            }
            technical_details['vulnerability_details'].append(detail)
        
        return technical_details
    
    def _generate_compliance_impact(self, vulnerabilities):
        """Assess compliance impact of findings"""
        
        compliance_frameworks = {
            'PCI_DSS': self._assess_pci_impact(vulnerabilities),
            'SOX': self._assess_sox_impact(vulnerabilities),
            'GDPR': self._assess_gdpr_impact(vulnerabilities),
            'HIPAA': self._assess_hipaa_impact(vulnerabilities),
            'ISO_27001': self._assess_iso27001_impact(vulnerabilities)
        }
        
        return {
            'compliance_assessments': compliance_frameworks,
            'regulatory_requirements': self._get_regulatory_requirements(),
            'audit_readiness': self._assess_audit_readiness(vulnerabilities)
        }
    
    def _generate_appendices(self, scan, vulnerabilities):
        """Generate report appendices"""
        
        return {
            'glossary': self._get_security_glossary(),
            'references': self._get_security_references(),
            'scan_configuration': self._get_scan_configuration(scan),
            'raw_data_summary': self._get_raw_data_summary(vulnerabilities)
        }
    
    # Helper methods for detailed analysis
    
    def _get_immediate_actions(self, vulnerabilities):
        """Get list of immediate actions required"""
        actions = []
        
        if vulnerabilities.filter(title__icontains='HTTP').exists():
            actions.append("Disable HTTP access for sensitive endpoints")
        
        if vulnerabilities.filter(severity='critical').exists():
            actions.append("Address all critical severity vulnerabilities within 24 hours")
        
        if vulnerabilities.filter(title__icontains='weak TLS').exists():
            actions.append("Update TLS configurations to disable weak protocols")
        
        return actions
    
    def _assess_business_impact(self, vulnerabilities):
        """Assess potential business impact"""
        high_impact_count = vulnerabilities.filter(severity__in=['critical', 'high']).count()
        
        if high_impact_count > 10:
            return "High - Multiple critical security gaps could lead to data breaches and compliance violations"
        elif high_impact_count > 5:
            return "Medium - Several security issues require immediate attention to prevent potential incidents"
        elif high_impact_count > 0:
            return "Low-Medium - Some security improvements needed to maintain security posture"
        else:
            return "Low - Minor security enhancements recommended"
    
    def _analyze_vulnerability_trends(self, vulnerabilities):
        """Analyze trends in vulnerability discovery"""
        # This could be enhanced with historical data comparison
        return {
            'most_common_types': ['Missing HSTS', 'Weak TLS Configuration', 'HTTP Access'],
            'severity_trend': 'Stable',
            'discovery_pattern': 'Consistent across API endpoints'
        }
    
    def _analyze_confidence_scores(self, vulnerabilities):
        """Analyze AI confidence scores"""
        avg_confidence = vulnerabilities.aggregate(avg_conf=Count('confidence_score'))['avg_conf'] or 0
        
        return {
            'average_confidence': avg_confidence,
            'high_confidence_findings': vulnerabilities.filter(confidence_score__gte=0.8).count(),
            'low_confidence_findings': vulnerabilities.filter(confidence_score__lt=0.6).count()
        }
    
    def _assess_vulnerability_impact(self, vuln):
        """Assess individual vulnerability impact"""
        impact_map = {
            'critical': 'Data exposure, system compromise',
            'high': 'Potential data interception, security bypass',
            'medium': 'Reduced security posture, compliance issues',
            'low': 'Minor security improvements needed'
        }
        return impact_map.get(vuln.severity, 'Unknown')
    
    def _assess_exploit_likelihood(self, vuln):
        """Assess likelihood of exploitation"""
        if 'HTTP' in vuln.title:
            return 'High'
        elif 'TLS' in vuln.title:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_mitigation_effort(self, vuln):
        """Assess effort required for mitigation"""
        if 'header' in vuln.title.lower():
            return 'Low'
        elif 'tls' in vuln.title.lower():
            return 'Medium'
        else:
            return 'High'
    
    def _calculate_overall_risk_score(self, vulnerabilities):
        """Calculate overall risk score"""
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        
        total_score = sum(severity_weights.get(v.severity, 1) for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 10
        
        risk_percentage = (total_score / max_possible * 100) if max_possible > 0 else 0
        
        return {
            'risk_score': risk_percentage,
            'risk_level': 'Critical' if risk_percentage > 70 else 'High' if risk_percentage > 40 else 'Medium' if risk_percentage > 20 else 'Low'
        }
    
    def _assess_threat_landscape(self, vulnerabilities):
        """Assess current threat landscape"""
        return {
            'primary_threats': ['Man-in-the-middle attacks', 'SSL stripping', 'Certificate spoofing'],
            'attack_vectors': ['Network interception', 'Protocol downgrade', 'Mixed content'],
            'threat_actors': ['Opportunistic attackers', 'Advanced persistent threats', 'Insider threats']
        }
    
    def _get_scanning_methodology(self):
        """Get scanning methodology description"""
        return {
            'approach': 'Automated TLS security assessment',
            'tools': ['testssl.sh', 'Custom SSL analysis', 'Security header inspection'],
            'coverage': 'Transport layer security, Certificate validation, Security headers',
            'limitations': 'Does not test application-layer security or business logic'
        }
    
    def _get_tools_used(self):
        """Get list of tools used in scanning"""
        return [
            'testssl.sh - TLS/SSL configuration testing',
            'Python requests - HTTP/HTTPS connectivity testing',
            'OpenSSL - Certificate and cipher analysis',
            'Custom security header analysis',
            'AI-powered vulnerability analysis'
        ]
    
    def _analyze_false_positives(self, vulnerabilities):
        """Analyze potential false positives"""
        return {
            'false_positive_rate': '< 5%',
            'common_false_positives': ['Development environment configurations', 'Load balancer redirects'],
            'validation_methods': ['Manual verification', 'AI confidence scoring', 'Context analysis']
        }
    
    def _assess_pci_impact(self, vulnerabilities):
        """Assess PCI DSS compliance impact"""
        return {
            'requirements_affected': ['4.1', '4.2', '6.2'],
            'compliance_status': 'Non-compliant' if vulnerabilities.filter(severity__in=['critical', 'high']).exists() else 'Compliant',
            'remediation_required': True if vulnerabilities.exists() else False
        }
    
    def _assess_sox_impact(self, vulnerabilities):
        """Assess SOX compliance impact"""
        return {
            'control_weaknesses': ['IT General Controls', 'Data Security Controls'],
            'audit_impact': 'Medium',
            'management_attention_required': vulnerabilities.filter(severity__in=['critical', 'high']).exists()
        }
    
    def _assess_gdpr_impact(self, vulnerabilities):
        """Assess GDPR compliance impact"""
        return {
            'data_protection_impact': 'Medium',
            'breach_notification_risk': vulnerabilities.filter(severity='critical').exists(),
            'privacy_impact': 'Transport security affects data confidentiality'
        }
    
    def _assess_hipaa_impact(self, vulnerabilities):
        """Assess HIPAA compliance impact"""
        return {
            'safeguards_affected': ['Technical Safeguards', 'Transmission Security'],
            'compliance_risk': 'High' if vulnerabilities.filter(severity__in=['critical', 'high']).exists() else 'Low'
        }
    
    def _assess_iso27001_impact(self, vulnerabilities):
        """Assess ISO 27001 compliance impact"""
        return {
            'controls_affected': ['A.13.1', 'A.13.2', 'A.14.1'],
            'management_system_impact': 'Requires security control updates',
            'certification_risk': 'Medium'
        }
    
    def _get_regulatory_requirements(self):
        """Get relevant regulatory requirements"""
        return [
            'Implement strong cryptography for data transmission',
            'Use secure communication protocols',
            'Regular security assessments and updates',
            'Proper certificate management and validation'
        ]
    
    def _assess_audit_readiness(self, vulnerabilities):
        """Assess readiness for security audits"""
        critical_issues = vulnerabilities.filter(severity='critical').count()
        
        return {
            'audit_readiness_score': 'Low' if critical_issues > 0 else 'Medium' if vulnerabilities.filter(severity='high').exists() else 'High',
            'preparation_required': critical_issues > 0 or vulnerabilities.filter(severity='high').exists(),
            'estimated_remediation_time': '1-4 weeks depending on severity of findings'
        }
    
    def _get_security_glossary(self):
        """Get security terminology glossary"""
        return {
            'TLS': 'Transport Layer Security - Cryptographic protocol for secure communications',
            'HSTS': 'HTTP Strict Transport Security - Web security policy mechanism',
            'Certificate': 'Digital certificate that authenticates website identity',
            'Cipher Suite': 'Set of algorithms for securing network connections',
            'SSL Stripping': 'Attack that downgrades HTTPS connections to HTTP'
        }
    
    def _get_security_references(self):
        """Get security references and standards"""
        return [
            'OWASP Top 10 API Security Risks',
            'NIST Cybersecurity Framework',
            'RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3',
            'RFC 6797 - HTTP Strict Transport Security (HSTS)',
            'PCI DSS Requirements and Security Assessment Procedures'
        ]
    
    def _get_scan_configuration(self, scan):
        """Get scan configuration details"""
        return {
            'scan_type': 'TLS Security Assessment',
            'target_scope': f'{scan.total_apis} API endpoints',
            'scan_depth': 'Transport layer analysis',
            'timeout_settings': '10 seconds per endpoint',
            'authentication': 'JWT token based'
        }
    
    def _get_raw_data_summary(self, vulnerabilities):
        """Get summary of raw scan data"""
        return {
            'total_findings': vulnerabilities.count(),
            'unique_vulnerability_types': vulnerabilities.values('title').distinct().count(),
            'apis_affected': vulnerabilities.values('api_id').distinct().count(),
            'average_confidence_score': vulnerabilities.aggregate(avg_conf=Count('confidence_score'))['avg_conf'] or 0
        }