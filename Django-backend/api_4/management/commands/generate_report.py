from django.core.management.base import BaseCommand
from django.template.loader import render_to_string
from django.utils import timezone
import json
from api_4.models import FileUploadScanResult, ScanSession, FileUploadTest

class Command(BaseCommand):
    help = 'Generate vulnerability report for a scan'
    
    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=int, help='Scan ID to generate report for')
        parser.add_argument(
            '--format',
            choices=['json', 'html', 'txt'],
            default='json',
            help='Report format (default: json)'
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path'
        )
        parser.add_argument(
            '--include-safe',
            action='store_true',
            help='Include safe APIs in the report'
        )
    
    def handle(self, *args, **options):
        scan_id = options['scan_id']
        format_type = options['format']
        output_file = options.get('output')
        include_safe = options['include_safe']
        
        try:
            # Get scan session
            scan_session = ScanSession.objects.get(scan_id=scan_id)
            
            # Get results
            results_query = FileUploadScanResult.objects.filter(scan_id=scan_id)
            if not include_safe:
                results_query = results_query.exclude(status='safe')
            
            results = results_query.order_by('-created_at')
            
            # Generate report data
            report_data = self._generate_report_data(scan_session, results)
            
            # Format and output
            if format_type == 'json':
                output = self._format_json_report(report_data)
            elif format_type == 'html':
                output = self._format_html_report(report_data)
            else:  # txt
                output = self._format_text_report(report_data)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.stdout.write(f'Report saved to {output_file}')
            else:
                self.stdout.write(output)
                
        except ScanSession.DoesNotExist:
            raise CommandError(f'Scan session {scan_id} not found')
        except Exception as e:
            raise CommandError(f'Failed to generate report: {str(e)}')
    
    def _generate_report_data(self, scan_session, results):
        """Generate structured report data"""
        vulnerable_results = results.filter(status='vulnerable')
        
        report_data = {
            'scan_info': {
                'scan_id': scan_session.scan_id,
                'started_at': scan_session.started_at,
                'completed_at': scan_session.completed_at,
                'status': scan_session.status,
                'total_apis': scan_session.total_apis,
                'vulnerable_apis': scan_session.vulnerable_apis,
            },
            'summary': {
                'total_tested': results.count(),
                'vulnerable': vulnerable_results.count(),
                'safe': results.filter(status='safe').count(),
                'errors': results.filter(status='error').count(),
            },
            'vulnerability_breakdown': {
                'webshell_upload': vulnerable_results.filter(webshell_upload_success=True).count(),
                'large_file_upload': vulnerable_results.filter(large_file_upload_success=True).count(),
                'unrestricted_files': vulnerable_results.filter(unrestricted_file_types=True).count(),
            },
            'vulnerable_apis': [],
            'recommendations': self._generate_recommendations(vulnerable_results)
        }
        
        # Add detailed vulnerable API information
        for result in vulnerable_results:
            api_data = {
                'name': result.api_name,
                'url': result.api_url,
                'method': result.api_method,
                'vulnerability_type': result.vulnerability_type,
                'risk_score': self._calculate_risk_score(result),
                'issues': [],
                'upload_tests': []
            }
            
            if result.webshell_upload_success:
                api_data['issues'].append('Allows webshell upload - CRITICAL RISK')
            if result.large_file_upload_success:
                api_data['issues'].append('Accepts large file uploads - DoS risk')
            if result.unrestricted_file_types:
                api_data['issues'].append('Accepts unrestricted file types')
            
            # Add test details
            for test in result.upload_tests.all():
                api_data['upload_tests'].append({
                    'file_name': test.file_name,
                    'file_type': test.file_type,
                    'test_type': test.test_type,
                    'success': test.upload_success,
                    'response_status': test.response_status
                })
            
            report_data['vulnerable_apis'].append(api_data)
        
        return report_data
    
    def _calculate_risk_score(self, result):
        """Calculate risk score for an API"""
        score = 0
        if result.webshell_upload_success:
            score += 70
        if result.large_file_upload_success:
            score += 20
        if result.unrestricted_file_types:
            score += 10
        return min(score, 100)
    
    def _generate_recommendations(self, vulnerable_results):
        """Generate security recommendations"""
        recommendations = []
        
        if vulnerable_results.filter(webshell_upload_success=True).exists():
            recommendations.extend([
                'Implement strict file type validation',
                'Use file content inspection, not just extension checking',
                'Store uploaded files outside the web root',
                'Implement file execution prevention',
                'Use antivirus scanning for uploaded files'
            ])
        
        if vulnerable_results.filter(large_file_upload_success=True).exists():
            recommendations.extend([
                'Implement file size limits',
                'Add rate limiting for file uploads',
                'Monitor disk space usage',
                'Implement upload quotas per user'
            ])
        
        if vulnerable_results.filter(unrestricted_file_types=True).exists():
            recommendations.extend([
                'Create whitelist of allowed file types',
                'Implement MIME type validation',
                'Use file signature verification',
                'Reject executable file formats'
            ])
        
        # General recommendations
        recommendations.extend([
            'Implement proper authentication and authorization',
            'Log all file upload activities',
            'Regular security testing of upload endpoints',
            'Use Content Security Policy (CSP) headers'
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _format_json_report(self, report_data):
        """Format report as JSON"""
        return json.dumps(report_data, indent=2, default=str)
    
    def _format_html_report(self, report_data):
        """Format report as HTML"""
        # Simple HTML template
        html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>File Upload Vulnerability Report - Scan {scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .vulnerability {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .recommendations {{ background: #e8f5e8; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>File Upload Vulnerability Report</h1>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Scan Status:</strong> {status}</p>
        <p><strong>Total APIs Tested:</strong> {total_tested}</p>
        <p><strong>Vulnerable APIs:</strong> <span class="critical">{vulnerable}</span></p>
    </div>
    
    <h2>Summary</h2>
    <ul>
        <li>Webshell Upload Vulnerabilities: <span class="critical">{webshell_count}</span></li>
        <li>Large File Upload Issues: <span class="high">{large_file_count}</span></li>
        <li>Unrestricted File Type Issues: <span class="medium">{unrestricted_count}</span></li>
    </ul>
    
    <h2>Vulnerable APIs</h2>
    {vulnerable_apis_html}
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
            {recommendations_html}
        </ul>
    </div>
</body>
</html>
        '''
        
        # Generate vulnerable APIs HTML
        vulnerable_apis_html = ''
        for api in report_data['vulnerable_apis']:
            risk_class = 'critical' if api['risk_score'] >= 70 else 'high' if api['risk_score'] >= 40 else 'medium'
            vulnerable_apis_html += f'''
            <div class="vulnerability">
                <h3>{api['name']} <span class="{risk_class}">Risk Score: {api['risk_score']}</span></h3>
                <p><strong>URL:</strong> {api['method']} {api['url']}</p>
                <p><strong>Issues:</strong></p>
                <ul>
                    {''.join(f'<li>{issue}</li>' for issue in api['issues'])}
                </ul>
            </div>
            '''
        
        # Generate recommendations HTML
        recommendations_html = ''.join(f'<li>{rec}</li>' for rec in report_data['recommendations'])
        
        return html_template.format(
            scan_id=report_data['scan_info']['scan_id'],
            status=report_data['scan_info']['status'],
            total_tested=report_data['summary']['total_tested'],
            vulnerable=report_data['summary']['vulnerable'],
            webshell_count=report_data['vulnerability_breakdown']['webshell_upload'],
            large_file_count=report_data['vulnerability_breakdown']['large_file_upload'],
            unrestricted_count=report_data['vulnerability_breakdown']['unrestricted_files'],
            vulnerable_apis_html=vulnerable_apis_html,
            recommendations_html=recommendations_html
        )
    
    def _format_text_report(self, report_data):
        """Format report as plain text"""
        report = f'''
FILE UPLOAD VULNERABILITY SCAN REPORT
=====================================

Scan ID: {report_data['scan_info']['scan_id']}
Status: {report_data['scan_info']['status']}
Started: {report_data['scan_info']['started_at']}
Completed: {report_data['scan_info']['completed_at']}

SUMMARY
-------
Total APIs Tested: {report_data['summary']['total_tested']}
Vulnerable APIs: {report_data['summary']['vulnerable']}
Safe APIs: {report_data['summary']['safe']}
Errors: {report_data['summary']['errors']}

VULNERABILITY BREAKDOWN
----------------------
Webshell Upload Vulnerabilities: {report_data['vulnerability_breakdown']['webshell_upload']}
Large File Upload Issues: {report_data['vulnerability_breakdown']['large_file_upload']}
Unrestricted File Type Issues: {report_data['vulnerability_breakdown']['unrestricted_files']}

VULNERABLE APIs
---------------
'''
        
        for api in report_data['vulnerable_apis']:
            report += f'''
API: {api['name']}
URL: {api['method']} {api['url']}
Risk Score: {api['risk_score']}/100
Vulnerability Type: {api['vulnerability_type']}
Issues:
'''
            for issue in api['issues']:
                report += f'  - {issue}\n'
            report += '\n'
        
        report += '''
RECOMMENDATIONS
---------------
'''
        for i, rec in enumerate(report_data['recommendations'], 1):
            report += f'{i}. {rec}\n'
        
        return report