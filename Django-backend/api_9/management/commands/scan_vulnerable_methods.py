from django.core.management.base import BaseCommand
from django.db import transaction
from api_orch.models import PostmanAPI
from api_9.models import VulnerableMethodScan
import requests
import logging
from urllib.parse import urljoin
import time


logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Scan APIs for vulnerable HTTP methods'
    
    # Vulnerable HTTP methods to check
    VULNERABLE_METHODS = ['PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT', 'PATCH', 'HEAD']
    
    # Method severity mapping
    METHOD_SEVERITY = {
        'DELETE': 'high',
        'PUT': 'medium',
        'PATCH': 'medium',
        'TRACE': 'medium',
        'TRACK': 'high',
        'CONNECT': 'critical',
        'HEAD': 'low',
    }
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--scan_id',
            type=str,
            required=True,
            help='The scan ID to process'
        )
    
    def handle(self, *args, **options):
        scan_id = options['scan_id']
        self.stdout.write(f"Starting vulnerability scan for scan_id: {scan_id}")
        
        try:
            # Get APIs from api_orch_postmanapi table
            apis = self.get_apis_by_scan_id(scan_id)
            
            if not apis:
                self.stdout.write(
                    self.style.WARNING(f"No APIs found for scan_id: {scan_id}")
                )
                return
            
            self.stdout.write(f"Found {len(apis)} APIs to scan")
            
            # Clear existing results for this scan_id
            VulnerableMethodScan.objects.filter(scan_id=scan_id).delete()
            
            vulnerabilities_found = 0
            
            for api in apis:
                try:
                    vulns = self.scan_api_methods(api, scan_id)
                    vulnerabilities_found += len(vulns)
                    
                    # Save vulnerabilities to database
                    if vulns:
                        VulnerableMethodScan.objects.bulk_create(vulns)
                        
                except Exception as e:
                    logger.error(f"Error scanning API {api.url}: {str(e)}")
                    continue
                
                # Add small delay to avoid overwhelming the target
                time.sleep(0.1)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Scan completed. Found {vulnerabilities_found} vulnerabilities."
                )
            )
            
        except Exception as e:
            logger.error(f"Scan failed for scan_id {scan_id}: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"Scan failed: {str(e)}")
            )
    
    def get_apis_by_scan_id(self, scan_id):
        """
        Get APIs from api_orch_postmanapi table by scan_id
        Adjust this method based on your actual model structure
        """
        try:
            # Adjust the filter condition based on your actual model structure
            # This assumes there's a scan_id field in the PostmanAPI model
            apis = PostmanAPI.objects.filter(scan_id=scan_id)
            return list(apis)
        except Exception as e:
            logger.error(f"Error retrieving APIs for scan_id {scan_id}: {str(e)}")
            return []
    
    def scan_api_methods(self, api, scan_id):
        """
        Scan a single API for vulnerable HTTP methods
        """
        vulnerabilities = []
        api_url = api.url  # Adjust based on your model field name
        
        self.stdout.write(f"Scanning: {api_url}")
        
        for method in self.VULNERABLE_METHODS:
            try:
                is_vulnerable, response_info = self.check_method_vulnerability(
                    api_url, method
                )
                
                if is_vulnerable:
                    vulnerability = VulnerableMethodScan(
                        scan_id=scan_id,
                        api_url=api_url,
                        vulnerable_method=method,
                        severity=self.METHOD_SEVERITY.get(method, 'medium'),
                        description=self.get_vulnerability_description(method),
                        response_status=response_info.get('status_code'),
                        response_headers=response_info.get('headers', {}),
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.stdout.write(
                        self.style.WARNING(
                            f"  VULNERABLE: {method} method allowed on {api_url}"
                        )
                    )
                
            except Exception as e:
                logger.error(f"Error checking {method} on {api_url}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def check_method_vulnerability(self, url, method):
        """
        Check if a specific HTTP method is vulnerable on the given URL
        """
        try:
            # Configure request session
            session = requests.Session()
            session.timeout = 10
            session.verify = False  # Disable SSL verification for testing
            
            # Prepare headers
            headers = {
                'User-Agent': 'Security-Scanner/1.0',
                'Accept': '*/*',
            }
            
            # Make the request
            response = session.request(
                method=method,
                url=url,
                headers=headers,
                allow_redirects=False
            )
            
            # Check if method is allowed
            is_vulnerable = self.is_method_vulnerable(response, method)
            
            response_info = {
                'status_code': response.status_code,
                'headers': dict(response.headers)
            }
            
            return is_vulnerable, response_info
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {method} {url}: {str(e)}")
            return False, {}
    
    def is_method_vulnerable(self, response, method):
        """
        Determine if the method is vulnerable based on response
        """
        # Method is vulnerable if:
        # 1. Status is not 405 (Method Not Allowed)
        # 2. Status is not 501 (Not Implemented)
        # 3. No explicit method rejection in Allow header
        
        if response.status_code in [405, 501]:
            return False
        
        # Check Allow header
        allow_header = response.headers.get('Allow', '').upper()
        if allow_header and method.upper() not in allow_header:
            return False
        
        # Additional checks for specific methods
        if method.upper() == 'TRACE':
            # TRACE is vulnerable if it returns the request
            return 'TRACE' in response.text.upper() or response.status_code == 200
        
        if method.upper() in ['PUT', 'DELETE', 'PATCH']:
            # These methods are vulnerable if they return success status
            return response.status_code in [200, 201, 202, 204]
        
        if method.upper() in ['TRACK', 'CONNECT']:
            # These methods should generally not be allowed
            return response.status_code not in [405, 501, 404]
        
        # Default: consider vulnerable if not explicitly rejected
        return response.status_code not in [405, 501, 404]
    
    def get_vulnerability_description(self, method):
        """
        Get description for vulnerability based on HTTP method
        """
        descriptions = {
            'PUT': 'PUT method is enabled and may allow unauthorized file uploads or data modification.',
            'DELETE': 'DELETE method is enabled and may allow unauthorized deletion of resources.',
            'TRACE': 'TRACE method is enabled and may lead to Cross-Site Tracing (XST) attacks.',
            'TRACK': 'TRACK method is enabled and may lead to Cross-Site Tracing attacks.',
            'CONNECT': 'CONNECT method is enabled and may allow proxy functionality abuse.',
            'PATCH': 'PATCH method is enabled and may allow partial resource modification.',
            'HEAD': 'HEAD method provides information about resources without proper access controls.',
        }
        return descriptions.get(method, f'{method} method is unnecessarily enabled.')