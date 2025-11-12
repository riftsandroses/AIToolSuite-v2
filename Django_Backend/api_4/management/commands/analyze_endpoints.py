from django.core.management.base import BaseCommand
from django.db import connection
import json
import re
from urllib.parse import urlparse

class Command(BaseCommand):
    help = 'Analyze API endpoints to identify potential file upload vulnerabilities'
    
    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=int, help='Scan ID to analyze')
        parser.add_argument(
            '--output-file',
            type=str,
            help='Output file for analysis results (JSON format)'
        )
    
    def handle(self, *args, **options):
        scan_id = options['scan_id']
        output_file = options.get('output_file')
        
        # Fetch APIs from database
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, "name", "method", "url", "headers", "body, "query_params"
                FROM api_orch_postmanapi
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            apis = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        analysis_results = []
        
        for api in apis:
            analysis = self._analyze_endpoint(api)
            analysis_results.append(analysis)
        
        # Print summary
        upload_candidates = [a for a in analysis_results if a['likely_file_upload']]
        
        self.stdout.write(f'Analyzed {len(apis)} APIs')
        self.stdout.write(f'Found {len(upload_candidates)} potential file upload endpoints')
        
        for candidate in upload_candidates:
            self.stdout.write(
                f'  - {candidate["api_name"]} ({candidate["method"]} {candidate["api_url"]})'
            )
            for indicator in candidate['risk_indicators']:
                self.stdout.write(f'    • {indicator}')
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            self.stdout.write(f'Analysis saved to {output_file}')
    
    def _analyze_endpoint(self, api):
        """Analyze an API endpoint for file upload potential"""
        analysis = {
            'api_id': api['id'],
            'api_name': api['name'],
            'api_url': api['url'],
            'method': api['method'],
            'likely_file_upload': False,
            'risk_indicators': [],
            'recommended_tests': []
        }
        
        method = api['method'].upper()
        url = api['url'].lower()
        name = api['name'].lower()
        
        # Method analysis
        if method in ['POST', 'PUT', 'PATCH']:
            analysis['risk_indicators'].append(f'Uses {method} method')
        else:
            return analysis  # Skip if not a mutation method
        
        # URL pattern analysis
        upload_keywords = [
            'upload', 'file', 'attachment', 'media', 'image', 'photo',
            'document', 'avatar', 'profile', 'import', 'csv', 'excel'
        ]
        
        url_indicators = [kw for kw in upload_keywords if kw in url or kw in name]
        if url_indicators:
            analysis['likely_file_upload'] = True
            analysis['risk_indicators'].append(f'URL/name contains: {", ".join(url_indicators)}')
        
        # Header analysis
        try:
            headers = json.loads(api.get('headers', '{}'))
            content_type = headers.get('Content-Type', '').lower()
            
            if 'multipart/form-data' in content_type:
                analysis['likely_file_upload'] = True
                analysis['risk_indicators'].append('Uses multipart/form-data content type')
            elif 'application/octet-stream' in content_type:
                analysis['likely_file_upload'] = True
                analysis['risk_indicators'].append('Uses binary content type')
        except:
            pass
        
        # Body analysis
        try:
            body = api.get('body', '')
            if body and ('file' in body.lower() or 'upload' in body.lower()):
                analysis['likely_file_upload'] = True
                analysis['risk_indicators'].append('Request body mentions file/upload')
        except:
            pass
        
        # Generate test recommendations
        if analysis['likely_file_upload']:
            analysis['recommended_tests'] = [
                'Test webshell upload (PHP, JSP, ASPX)',
                'Test large file upload (DoS)',
                'Test executable file upload',
                'Test file type restrictions',
                'Test file size limits'
            ]
        
        return analysis