import json
import sys
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.utils import timezone
from api_2.services import APISecurityScannerTC1
from api_2.models import ScanSessionTC1, ScanResultTC1
from api_2.utils.security_checks import ReportGeneratorTC1

class Command(BaseCommand):
    help = 'Run security scan from command line'

    def add_arguments(self, parser):
        parser.add_argument(
            'scan_id',
            type=int,
            help='Scan ID to process'
        )
        parser.add_argument(
            '--user-id',
            type=int,
            default=1,
            help='User ID to run scan as (default: 1)'
        )
        parser.add_argument(
            '--output-format',
            choices=['json', 'text', 'csv'],
            default='text',
            help='Output format for results'
        )
        parser.add_argument(
            '--output-file',
            type=str,
            help='Output file path (optional)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='JSON configuration for scan (optional)'
        )
        parser.add_argument(
            '--report',
            action='store_true',
            help='Generate detailed vulnerability report'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )

    def handle(self, *args, **options):
        scan_id = options['scan_id']
        user_id = options['user_id']
        output_format = options['output_format']
        output_file = options['output_file']
        config_str = options.get('config')
        generate_report = options['report']
        verbose = options['verbose']

        try:
            # Get user
            user = User.objects.get(id=user_id)
            
            # Parse config if provided
            scan_config = {}
            if config_str:
                try:
                    scan_config = json.loads(config_str)
                except json.JSONDecodeError:
                    raise CommandError(f"Invalid JSON config: {config_str}")

            if verbose:
                self.stdout.write(f"Starting security scan for scan_id: {scan_id}")
                self.stdout.write(f"User: {user.username}")
                self.stdout.write(f"Config: {scan_config}")

            # Initialize scanner
            scanner = APISecurityScannerTC1(user=user)

            # Run scan
            result = scanner.initiate_scan(scan_id, scan_config)

            if not result.get('success'):
                raise CommandError(f"Scan failed: {result.get('error', 'Unknown error')}")

            if verbose:
                self.stdout.write(self.style.SUCCESS(f"Scan completed successfully"))
                self.stdout.write(f"Total APIs scanned: {result.get('total_apis', 0)}")

            # Get scan results
            scan_results = ScanResultTC1.objects.filter(scan_id=scan_id)
            
            if output_format == 'json':
                output_data = self._format_json_output(scan_results, generate_report)
            elif output_format == 'csv':
                output_data = self._format_csv_output(scan_results)
            else:
                output_data = self._format_text_output(scan_results, verbose, generate_report)

            # Output results
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output_data)
                self.stdout.write(self.style.SUCCESS(f"Results written to: {output_file}"))
            else:
                self.stdout.write(output_data)

        except User.DoesNotExist:
            raise CommandError(f"User with ID {user_id} does not exist")
        except Exception as e:
            raise CommandError(f"Error running scan: {str(e)}")

    def _format_json_output(self, scan_results, generate_report=False):
        """Format output as JSON"""
        results_data = []
        
        for result in scan_results:
            results_data.append({
                'id': result.id,
                'scan_id': result.scan_id,
                'api_name': result.api_name,
                'api_method': result.api_method,
                'api_url': result.api_url,
                'vulnerability_type': result.vulnerability_type,
                'severity': result.severity,
                'title': result.title,
                'description': result.description,
                'impact': result.impact,
                'recommendation': result.recommendation,
                'status': result.status,
                'scan_started_at': result.scan_started_at.isoformat() if result.scan_started_at else None,
                'scan_completed_at': result.scan_completed_at.isoformat() if result.scan_completed_at else None,
            })

        output = {
            'scan_results': results_data,
            'summary': {
                'total_results': len(results_data),
                'vulnerabilities_by_severity': self._count_by_field(scan_results, 'severity'),
                'vulnerabilities_by_type': self._count_by_field(scan_results, 'vulnerability_type'),
            }
        }

        if generate_report:
            report = ReportGeneratorTC1.generate_vulnerability_report(results_data)
            output['detailed_report'] = report

        return json.dumps(output, indent=2)

    def _format_csv_output(self, scan_results):
        """Format output as CSV"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = [
            'ID', 'Scan ID', 'API Name', 'Method', 'URL', 'Vulnerability Type',
            'Severity', 'Title', 'Description', 'Impact', 'Recommendation',
            'Status', 'Scan Started', 'Scan Completed'
        ]
        writer.writerow(headers)
        
        # Write data
        for result in scan_results:
            writer.writerow([
                result.id,
                result.scan_id,
                result.api_name,
                result.api_method,
                result.api_url,
                result.vulnerability_type,
                result.severity,
                result.title,
                result.description,
                result.impact,
                result.recommendation,
                result.status,
                result.scan_started_at.isoformat() if result.scan_started_at else '',
                result.scan_completed_at.isoformat() if result.scan_completed_at else '',
            ])
        
        return output.getvalue()

    def _format_text_output(self, scan_results, verbose=False, generate_report=False):
        """Format output as human-readable text"""
        output = []
        
        # Header
        output.append("="*80)
        output.append("API SECURITY SCAN RESULTS")
        output.append("="*80)
        output.append(f"Generated at: {timezone.now().isoformat()}")
        output.append(f"Total results: {len(scan_results)}")
        output.append("")
        
        # Summary by severity
        severity_counts = self._count_by_field(scan_results, 'severity')
        output.append("VULNERABILITY SUMMARY BY SEVERITY:")
        output.append("-" * 40)
        for severity, count in severity_counts.items():
            output.append(f"  {severity.upper()}: {count}")
        output.append("")
        
        # Summary by type
        type_counts = self._count_by_field(scan_results, 'vulnerability_type')
        output.append("VULNERABILITY SUMMARY BY TYPE:")
        output.append("-" * 40)
        for vuln_type, count in type_counts.items():
            output.append(f"  {vuln_type.replace('_', ' ').title()}: {count}")
        output.append("")
        
        # Detailed results
        if verbose or len(scan_results) <= 10:
            output.append("DETAILED FINDINGS:")
            output.append("-" * 40)
            
            for i, result in enumerate(scan_results, 1):
                output.append(f"{i}. {result.title}")
                output.append(f"   API: {result.api_name} ({result.api_method} {result.api_url})")
                output.append(f"   Severity: {result.severity.upper()}")
                output.append(f"   Type: {result.vulnerability_type.replace('_', ' ').title()}")
                
                if verbose:
                    output.append(f"   Description: {result.description}")
                    output.append(f"   Impact: {result.impact}")
                    output.append(f"   Recommendation: {result.recommendation}")
                
                output.append("")
        else:
            output.append(f"Use --verbose flag to see detailed findings for all {len(scan_results)} results")
            output.append("")
        
        # Generate detailed report if requested
        if generate_report:
            output.append("="*80)
            output.append("DETAILED VULNERABILITY REPORT")
            output.append("="*80)
            
            results_data = []
            for result in scan_results:
                results_data.append({
                    'api_name': result.api_name,
                    'severity': result.severity,
                    'vulnerability_type': result.vulnerability_type,
                    'title': result.title,
                    'impact': result.impact,
                    'recommendation': result.recommendation
                })
            
            report = ReportGeneratorTC1.generate_vulnerability_report(results_data)
            
            output.append(f"Overall Risk Score: {report['summary']['overall_risk_score']}/100")
            output.append("")
            
            output.append("RECOMMENDATIONS:")
            for i, rec in enumerate(report.get('recommendations', []), 1):
                output.append(f"{i}. {rec}")
            output.append("")
        
        return "\n".join(output)

    def _count_by_field(self, queryset, field_name):
        """Count occurrences of field values"""
        counts = {}
        for item in queryset:
            value = getattr(item, field_name)
            counts[value] = counts.get(value, 0) + 1
        return counts