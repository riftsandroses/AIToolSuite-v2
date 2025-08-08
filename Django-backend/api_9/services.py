# services.py
import openai
from openai import OpenAI
import subprocess
import json
import logging
import shutil
import os
import time
import re
import requests
import asyncio
import aiohttp
from typing import List, Dict, Tuple, Any, Optional
from asgiref.sync import sync_to_async
from urllib.parse import urlparse, urljoin
from django.db import connection, transaction
from django.conf import settings
from api_orch.models import PostmanAPI
from .models import SubdomainDiscovery, DocumentationEndpoint
import logging


logger = logging.getLogger(__name__)


class ChatGPTService:
    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
    
    def extract_base_url(self, api_url):
        try:
            # First try to parse the URL directly without ChatGPT
            parsed = urlparse(api_url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
            
            # If direct parsing fails, try to clean the URL first
            # Remove common prefixes/suffixes that might be present
            clean_url = api_url.strip()
            for prefix in ['The base URL extracted from the provided API URL is:', 
                        'The base URL extracted from the provided API endpoint is:',
                        'Base URL:']:
                if clean_url.startswith(prefix):
                    clean_url = clean_url[len(prefix):].strip()
            
            # Remove any surrounding quotes or punctuation
            clean_url = clean_url.strip('"').strip("'").strip().rstrip('.').rstrip(',').rstrip(':')
            
            # Try parsing again
            parsed = urlparse(clean_url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
            
            # If still failing, use ChatGPT as last resort
            prompt = f"""
            Extract ONLY the base URL from this text. Return ONLY the URL in format http(s)://domain.tld. 
            DO NOT include any other text, explanations, or labels.

            Text: {api_url}
            """
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "Extract and return only the base URL (scheme + domain) from the given text. Example: https://example.com. Return ONLY the URL with no other text."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=20,
                temperature=0
            )

            raw_output = response.choices[0].message.content.strip()
            
            # Final cleanup attempt
            for token in raw_output.split():
                if token.startswith("http://") or token.startswith("https://"):
                    parsed = urlparse(token)
                    if parsed.scheme and parsed.netloc:
                        return f"{parsed.scheme}://{parsed.netloc}"
            
            # If everything fails, return the original URL's base
            parsed = urlparse(api_url)
            return f"{parsed.scheme}://{parsed.netloc}"

        except Exception as e:
            logger.error(f"Error extracting base URL: {str(e)}")
            parsed = urlparse(api_url)
            return f"{parsed.scheme}://{parsed.netloc}"
    
    def analyze_environment(self, subdomain):
        try:
            prompt = f"""
            Analyze this URL/subdomain: {subdomain}

            Based on the URL structure, subdomain name, and common patterns, determine if this appears to be:
            1. Development environment
            2. Staging environment  
            3. Production environment
            4. Unknown/uncertain

            Respond with ONLY one of these words: dev, staging, production, unknown
            """

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert at identifying development, staging, and production environments from URLs. Respond with only one word: dev, staging, production, or unknown."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=10,
                temperature=0
            )

            result = response.choices[0].message.content.strip().lower()
            valid_responses = ['dev', 'staging', 'production', 'unknown']
            if result in valid_responses:
                return result, response.choices[0].message.content
            else:
                return 'unknown', response.choices[0].message.content

        except Exception as e:
            logger.error(f"Error analyzing environment with ChatGPT: {str(e)}")
            return 'unknown', f"Error: {str(e)}"

class SubdomainDiscoveryService:
    def __init__(self):
        self.chatgpt_service = ChatGPTService()
        # Try to find the full path to subfinder and httpx
        self.subfinder_path = self._find_executable('subfinder')
        self.httpx_path = os.path.expanduser('~/go/bin/httpx')
    
    def _find_executable(self, name):
        """Find the full path to an executable"""
        # First try using shutil.which
        path = shutil.which(name)
        if path:
            logger.info(f"Found {name} at: {path}")
            return path
        
        # Common installation paths to check
        common_paths = [
            f'/usr/local/bin/{name}',
            f'/usr/bin/{name}',
            f'/opt/homebrew/bin/{name}',  # macOS Homebrew
            f'/home/{os.getenv("USER", "ubuntu")}/go/bin/{name}',  # Go binary path
            f'{os.path.expanduser("~")}/go/bin/{name}',
            f'/snap/bin/{name}',  # Snap packages
        ]
        
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                logger.info(f"Found {name} at: {path}")
                return path
        
        logger.error(f"Could not find {name} executable")
        return name  # Fallback to just the name
    
    def run_subfinder(self, domain):
        """Run subfinder to discover subdomains"""
        try:
            # Use full path to subfinder
            cmd = [self.subfinder_path, '-d', domain, '-silent', '-o', '/tmp/subdomains.txt']
            
            # Set up environment with common paths
            env = os.environ.copy()
            env['PATH'] = '/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:' + \
                         f'{os.path.expanduser("~")}/go/bin:/snap/bin:' + env.get('PATH', '')
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
            
            if result.returncode == 0:
                if os.path.exists('/tmp/subdomains.txt'):
                    with open('/tmp/subdomains.txt', 'r') as f:
                        subdomains = [line.strip() for line in f.readlines() if line.strip()]
                    logger.info(f"Found {len(subdomains)} subdomains")
                    return subdomains
                else:
                    logger.warning("Subdomains file not created")
                    return []
            else:
                logger.error(f"Subfinder error (return code {result.returncode}): {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error("Subfinder timeout")
            return []
        except FileNotFoundError:
            logger.error(f"Subfinder executable not found at: {self.subfinder_path}")
            return []
        except Exception as e:
            logger.error(f"Error running subfinder: {str(e)}")
            return []
    
    def check_live_subdomains(self, subdomains):
        """Use httpx to check which subdomains are live"""
        try:
            # Write subdomains to temporary file
            with open('/tmp/subdomains_input.txt', 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            
            # Updated httpx command without -l flag
            cmd = [
                self.httpx_path,
                '-list', '/tmp/subdomains_input.txt',  # Use -list instead of -l
                '-silent',
                '-status-code',
                '-o', '/tmp/live_subdomains.txt'
            ]
            
            # Set up environment with common paths
            env = os.environ.copy()
            env['PATH'] = '/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:' + \
                        f'{os.path.expanduser("~")}/go/bin:/snap/bin:' + env.get('PATH', '')
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
            
            live_subdomains = []
            if result.returncode == 0:
                if os.path.exists('/tmp/live_subdomains.txt'):
                    with open('/tmp/live_subdomains.txt', 'r') as f:
                        for line in f.readlines():
                            if line.strip():
                                # httpx output format: URL [STATUS_CODE]
                                url = line.split()[0].strip()
                                live_subdomains.append(url)
                    logger.info(f"Found {len(live_subdomains)} live subdomains")
                else:
                    logger.warning("Live subdomains file not created")
            else:
                logger.error(f"Httpx error (return code {result.returncode}): {result.stderr}")
            
            return live_subdomains
            
        except subprocess.TimeoutExpired:
            logger.error("Httpx timeout")
            return []
        except FileNotFoundError:
            logger.error(f"Httpx executable not found at: {self.httpx_path}")
            return []
        except Exception as e:
            logger.error(f"Error running httpx: {str(e)}")
            return []
    
    def process_scan(self, scan_id):
        """Main method to process subdomain discovery for a scan_id"""
        try:
            # Check if tools are available
            if not os.path.exists(self.subfinder_path.split()[0]) and not shutil.which('subfinder'):
                return {'error': 'Subfinder tool not found. Please install subfinder.'}
            
            if not os.path.exists(self.httpx_path.split()[0]) and not shutil.which('httpx'):
                return {'error': 'Httpx tool not found. Please install httpx.'}
            
            # Get APIs associated with scan_id
            apis = PostmanAPI.objects.filter(scan_id=scan_id)
            
            if not apis.exists():
                return {'error': f'No APIs found for scan_id: {scan_id}'}
            
            base_urls = set()
            
            # Extract base URLs using ChatGPT
            for api in apis:
                base_url = self.chatgpt_service.extract_base_url(api.url)
                if base_url:
                    base_urls.add(base_url)
            
            if not base_urls:
                return {'error': 'No valid base URLs extracted'}
            
            results = {
                'scan_id': scan_id,
                'base_urls': list(base_urls),
                'discovered_subdomains': [],
                'total_live_subdomains': 0
            }
            
            # Process each base URL
            for base_url in base_urls:
                parsed_url = urlparse(base_url)
                domain = parsed_url.netloc.strip()
                
                if not domain:
                    logger.warning(f"Skipping base_url '{base_url}' due to missing domain/netloc.")
                    continue
                
                # Discover subdomains
                subdomains = self.run_subfinder(domain)
                
                if subdomains:
                    # Check which subdomains are live
                    live_subdomains = self.check_live_subdomains(subdomains)
                    
                    # Analyze and save live subdomains
                    for subdomain_url in live_subdomains:
                        env_type, chatgpt_response = self.chatgpt_service.analyze_environment(subdomain_url)
                        
                        # Save to database
                        subdomain_obj, created = SubdomainDiscovery.objects.get_or_create(
                            scan_id=scan_id,
                            subdomain=subdomain_url,
                            defaults={
                                'base_url': base_url,
                                'environment_type': env_type,
                                'chatgpt_response': chatgpt_response,
                                'status': 'live'
                            }
                        )
                        
                        if not created:
                            # Update existing record
                            subdomain_obj.environment_type = env_type
                            subdomain_obj.chatgpt_response = chatgpt_response
                            subdomain_obj.save()
                        
                        results['discovered_subdomains'].append({
                            'subdomain': subdomain_url,
                            'base_url': base_url,
                            'environment_type': env_type,
                            'created': created
                        })
            
            results['total_live_subdomains'] = len(results['discovered_subdomains'])
            return results
            
        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {str(e)}")
            return {'error': str(e)}

class DocumentationScanner:
    # Common documentation endpoints to check
    DOC_ENDPOINTS = [
        '/swagger/',
        '/swagger.json',
        '/swagger.yaml',
        '/swagger/index.html',
        '/api/swagger/',
        '/api/swagger.json',
        '/api/swagger.yaml',
        '/docs/',
        '/api/docs/',
        '/documentation/',
        '/api/documentation/',
        '/openapi.json',
        '/openapi.yaml',
        '/api/openapi.json',
        '/api/openapi.yaml',
        '/redoc/',
        '/api/redoc/',
        '/api-docs/',
        '/api/v1/docs/',
        '/api/v2/docs/',
        '/spec/',
        '/api/spec/',
        '/.well-known/schema',
        '/schema/',
        '/api/schema/',
        '/graphql',
        '/api/graphql',
    ]

    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def scan_base_urls(self, base_urls):
        """Scan multiple base URLs for documentation endpoints"""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = []
            for base_url in base_urls:
                tasks.append(self._scan_single_base_url(session, base_url))
            
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_single_base_url(self, session, base_url):
        """Scan a single base URL for all documentation endpoints"""
        base_url = base_url.rstrip('/')
        
        tasks = []
        for endpoint in self.DOC_ENDPOINTS:
            full_url = urljoin(base_url + '/', endpoint.lstrip('/'))
            tasks.append(self._check_endpoint(session, base_url, full_url, endpoint))
        
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_endpoint(self, session, base_url, endpoint_url, endpoint_path):
        """Check a specific endpoint for documentation"""
        try:
            headers = {
                'User-Agent': 'API-Documentation-Scanner/1.0',
                'Accept': 'application/json, text/html, application/yaml, text/yaml, */*'
            }
            
            async with session.get(endpoint_url, headers=headers, allow_redirects=True) as response:
                status_code = response.status
                content_type = response.headers.get('content-type', '').lower()
                
                # Only process successful or forbidden responses (not 404, 500, etc.)
                if status_code in [200, 401, 403]:
                    # Read response content (limit to avoid memory issues)
                    content = await response.text()
                    response_size = len(content)
                    response_preview = content[:1000] if content else ""
                    
                    # Determine documentation type
                    doc_type = self._determine_doc_type(endpoint_path, content_type, content)
                    
                    # Determine status
                    status = self._get_status(status_code)
                    
                    # Save to database
                    await self._save_endpoint(
                        base_url=base_url,
                        endpoint_url=endpoint_url,
                        doc_type=doc_type,
                        status_code=status_code,
                        status=status,
                        content_type=content_type,
                        response_size=response_size,
                        response_preview=response_preview
                    )
                    
                    logger.info(f"Found documentation endpoint: {endpoint_url} ({status_code})")
                    
        except asyncio.TimeoutError:
            logger.warning(f"Timeout checking {endpoint_url}")
        except Exception as e:
            logger.error(f"Error checking {endpoint_url}: {str(e)}")

    def _determine_doc_type(self, endpoint_path, content_type, content):
        """Determine the type of documentation based on URL and content"""
        endpoint_lower = endpoint_path.lower()
        content_lower = content.lower() if content else ""
        
        if 'swagger' in endpoint_lower:
            return 'swagger'
        elif 'openapi' in endpoint_lower:
            return 'openapi'
        elif 'redoc' in endpoint_lower:
            return 'redoc'
        elif 'docs' in endpoint_lower or 'documentation' in endpoint_lower:
            return 'docs'
        elif 'api-docs' in endpoint_lower:
            return 'api-docs'
        elif any(term in content_lower for term in ['swagger', 'openapi']):
            return 'swagger'
        else:
            return 'other'

    def _get_status(self, status_code):
        """Convert status code to status category"""
        if status_code == 200:
            return 'success'
        elif status_code == 401:
            return 'unauthorized'
        elif status_code == 403:
            return 'forbidden'
        else:
            return 'other'

    async def _save_endpoint(self, **kwargs):
        """Save endpoint data to database"""
        @sync_to_async
        def _save():
            DocumentationEndpoint.objects.update_or_create(
                scan_id=self.scan_id,
                endpoint_url=kwargs['endpoint_url'],
                defaults={
                    'base_url': kwargs['base_url'],
                    'doc_type': kwargs['doc_type'],
                    'status_code': kwargs['status_code'],
                    'status': kwargs['status'],
                    'response_content_type': kwargs['content_type'],
                    'response_size': kwargs['response_size'],
                    'response_preview': kwargs['response_preview'],
                }
            )
        
        await _save()


@sync_to_async
def get_base_urls_from_scan_id(scan_id):
    """Get base URLs from api_orch_postmanapi table"""
    
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT url 
            FROM api_orch_postmanapi 
            WHERE scan_id = %s AND url IS NOT NULL
        """, [scan_id])
        
        rows = cursor.fetchall()
        base_urls = [row[0] for row in rows if row[0]]
        
    return base_urls


async def run_documentation_scan(scan_id):
    """Main function to run the documentation scan"""
    try:
        # Get base URLs from the database
        base_urls = await get_base_urls_from_scan_id(scan_id)
        
        if not base_urls:
            logger.warning(f"No base URLs found for scan_id: {scan_id}")
            return {"status": "error", "message": "No base URLs found"}
        
        logger.info(f"Starting documentation scan for {len(base_urls)} base URLs")
        
        # Run the scan
        scanner = DocumentationScanner(scan_id)
        await scanner.scan_base_urls(base_urls)
        
        # Get results count
        @sync_to_async
        def get_results_count():
            return DocumentationEndpoint.objects.filter(scan_id=scan_id).count()

        results_count = await get_results_count()
        
        return {
            "status": "success", 
            "message": f"Scan completed. Found {results_count} documentation endpoints.",
            "scanned_urls": len(base_urls),
            "results_count": results_count
        }
        
    except Exception as e:
        logger.error(f"Documentation scan failed: {str(e)}")
        return {"status": "error", "message": str(e)}


class APIVersionEnumerator:
    def __init__(self, use_openai=False):
        self.use_openai = use_openai
        if use_openai:
            openai_api_key = getattr(settings, 'OPENAI_API_KEY', None)
            if openai_api_key:
                openai.api_key = openai_api_key
            else:
                raise ValueError("OPENAI_API_KEY not found in settings.py")
        
        # Common version patterns to check
        self.version_patterns = [
            'v1', 'v2', 'v3', 'v4', 'v5',
            'api/v1', 'api/v2', 'api/v3', 'api/v4', 'api/v5',
            'alpha', 'beta', 'dev', 'test', 'staging',
            'v1.0', 'v1.1', 'v1.2', 'v2.0', 'v2.1',
            '1.0', '1.1', '1.2', '2.0', '2.1',
            'latest', 'stable', 'preview'
        ]
    
    def extract_base_url(self, api_url: str) -> str:
        """Extract base URL from API endpoint"""
        parsed = urlparse(api_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Remove common version patterns from path
        path = parsed.path
        for pattern in ['v1', 'v2', 'v3', 'v4', 'v5', 'api/v1', 'api/v2', 'alpha', 'beta']:
            if pattern in path:
                path = path.replace(f'/{pattern}', '').replace(f'{pattern}/', '')
        
        return base_url + path if path != '/' else base_url
    
    async def check_url_accessibility(self, session: aiohttp.ClientSession, url: str) -> Tuple[bool, int, float, str]:
        """Check if URL is accessible and return status"""
        start_time = time.time()
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                response_time = time.time() - start_time
                return True, response.status, response_time, None
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return False, 408, response_time, "Request timeout"
        except Exception as e:
            response_time = time.time() - start_time
            return False, 0, response_time, str(e)
    
    async def enumerate_versions_async(self, api_urls: List[str]) -> List[Dict]:
        """Asynchronously check multiple API versions"""
        results = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for api_url in api_urls:
                base_url = self.extract_base_url(api_url)
                
                # Generate version URLs to check
                version_urls = self.generate_version_urls(base_url, api_url)
                
                for version, version_url in version_urls:
                    task = self.check_single_version(session, api_url, version, version_url)
                    tasks.append(task)
            
            # Execute all checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            valid_results = [r for r in results if isinstance(r, dict)]
            
        return valid_results
    
    async def check_single_version(self, session: aiohttp.ClientSession, original_url: str, version: str, version_url: str) -> Dict:
        """Check a single version URL"""
        is_accessible, status_code, response_time, error = await self.check_url_accessibility(session, version_url)
        
        return {
            'original_api_url': original_url,
            'version': version,
            'version_url': version_url,
            'is_accessible': is_accessible,
            'response_status_code': status_code,
            'response_time': response_time,
            'error_message': error
        }
    
    def generate_version_urls(self, base_url: str, original_url: str) -> List[Tuple[str, str]]:
        """Generate list of version URLs to check"""
        version_urls = []
        parsed = urlparse(original_url)
        
        for version in self.version_patterns:
            # Method 1: Replace in path
            if '/api/' in parsed.path:
                new_path = parsed.path.replace('/api/', f'/api/{version}/')
                version_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                version_urls.append((version, version_url))
            
            # Method 2: Add version to base path
            version_url = urljoin(base_url, f"/{version}")
            if version_url not in [vu[1] for vu in version_urls]:
                version_urls.append((version, version_url))
            
            # Method 3: Add version as subdomain
            if not parsed.netloc.startswith(version):
                subdomain_url = f"{parsed.scheme}://{version}.{parsed.netloc}{parsed.path}"
                version_urls.append((f"{version}-subdomain", subdomain_url))
        
        return version_urls
    
    def get_openai_suggestions(self, api_url: str) -> List[str]:
        """Use OpenAI to suggest potential version endpoints"""
        if not self.use_openai:
            return []
        
        try:
            prompt = f"""
            Given this API endpoint: {api_url}
            
            Suggest 10 potential version endpoints that might exist for this API.
            Consider common patterns like:
            - Version numbers (v1, v2, etc.)
            - Semantic versioning (v1.0, v2.1, etc.)
            - Environment versions (alpha, beta, dev, staging)
            - Path-based versioning
            - Subdomain-based versioning
            
            Return only the URLs, one per line, no explanations.
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3
            )
            
            suggestions = response.choices[0].message.content.strip().split('\n')
            return [s.strip() for s in suggestions if s.strip().startswith('http')]
            
        except Exception as e:
            print(f"OpenAI API error: {e}")
            return []


class TC6EndpointDiscoveryService:
    
    COMMON_ENDPOINTS = {
        'health': [
            '/health',
            '/health-check',
            '/healthcheck',
            '/api/health',
            '/status',
            '/ping',
            '/alive',
            '/ready'
        ],
        'debug': [
            '/debug',
            '/api/debug',
            '/debug/info',
            '/debug/status',
            '/__debug__',
            '/dev/debug',
            '/admin/debug'
        ],
        'monitoring': [
            '/metrics',
            '/api/metrics',
            '/monitoring',
            '/api/monitoring',
            '/stats',
            '/api/stats',
            '/info',
            '/api/info',
            '/actuator/health',
            '/actuator/info',
            '/actuator/metrics'
        ]
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 10
        # Set a reasonable user agent
        self.session.headers.update({
            'User-Agent': 'API-Health-Checker/1.0'
        })
        self.access_token = None
    
    def get_access_token_by_scan_id(self, scan_id: str) -> Optional[str]:
        """Fetch access token from api_orch_scantokens table by scan_id"""
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT access_token 
                    FROM api_orch_scantokens 
                    WHERE scan_id = %s
                    LIMIT 1
                """, [scan_id])
                
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    logger.warning(f"No access token found for scan_id: {scan_id}")
                    return None
        except Exception as e:
            logger.error(f"Error fetching access token for scan_id {scan_id}: {e}")
            return None
    
    def get_apis_by_scan_id(self, scan_id: str) -> List[Dict[str, Any]]:
        """Fetch APIs from api_orch_postmanapi table by scan_id"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, name, url
                FROM api_orch_postmanapi 
                WHERE scan_id = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def discover_endpoints_with_ai(self, api_info: Dict[str, Any]) -> List[str]:
        """Use OpenAI to suggest additional endpoints based on API info"""
        try:
            if not hasattr(settings, 'OPENAI_API_KEY') or not settings.OPENAI_API_KEY:
                return []
                
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            
            prompt = f"""
            Given an API with the following information:
            Name: {api_info.get('name', 'Unknown')}
            Base URL: {api_info.get('url', '')}
            
            Suggest 5-10 additional common endpoint paths that this API might have for:
            1. Health checks
            2. Debug information
            3. Monitoring/metrics
            
            Return only the paths (starting with '/'), one per line, without explanations.
            Focus on realistic, commonly used endpoints.
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )
            
            suggested_paths = []
            for line in response.choices[0].message.content.strip().split('\n'):
                line = line.strip()
                if line.startswith('/') and len(line) > 1:
                    suggested_paths.append(line)
            
            return suggested_paths[:10]  # Limit to 10 suggestions
            
        except Exception as e:
            logger.error(f"OpenAI endpoint discovery failed: {e}")
            return []
    
    def categorize_endpoint(self, path: str) -> str:
        """Categorize endpoint based on path"""
        path_lower = path.lower()
        
        if any(keyword in path_lower for keyword in ['health', 'alive', 'ready', 'ping', 'status']):
            return 'health'
        elif any(keyword in path_lower for keyword in ['debug', '__debug__']):
            return 'debug'
        elif any(keyword in path_lower for keyword in ['metrics', 'monitoring', 'stats', 'info', 'actuator']):
            return 'monitoring'
        else:
            # Try to guess based on common patterns
            if 'debug' in path_lower:
                return 'debug'
            elif any(keyword in path_lower for keyword in ['metric', 'monitor', 'stat', 'info']):
                return 'monitoring'
            else:
                return 'health'  # default
    
    def check_endpoint(self, base_url: str, endpoint_path: str, use_auth: bool = True) -> Dict[str, Any]:
        """Check if an endpoint is accessible and get response details"""
        full_url = urljoin(base_url.rstrip('/') + '/', endpoint_path.lstrip('/'))
        
        result = {
            'endpoint_url': full_url,
            'status_code': None,
            'response_time': None,
            'is_accessible': False,
            'error_message': None,
            'auth_used': use_auth and self.access_token is not None
        }
        
        # Prepare headers
        headers = {}
        if use_auth and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        
        try:
            start_time = time.time()
            response = self.session.get(full_url, headers=headers, allow_redirects=True)
            end_time = time.time()
            
            result['status_code'] = response.status_code
            result['response_time'] = end_time - start_time
            
            # Consider endpoint accessible if status is not in error range
            if response.status_code not in [400, 401, 403, 404, 500, 501, 502, 503, 504]:
                result['is_accessible'] = True
            else:
                result['error_message'] = f"HTTP {response.status_code}"
                
                # If we got 401 and we used auth, also try without auth
                if response.status_code == 401 and use_auth and self.access_token:
                    logger.info(f"Got 401 with auth token, trying without auth for: {full_url}")
                    fallback_result = self.check_endpoint(base_url, endpoint_path, use_auth=False)
                    
                    # If it works without auth, update the result but note the auth issue
                    if fallback_result['is_accessible']:
                        result.update(fallback_result)
                        result['error_message'] = "Accessible without auth (token may be invalid/expired)"
                        result['auth_used'] = False
                
        except requests.exceptions.RequestException as e:
            result['error_message'] = str(e)
            result['response_time'] = 0
            
        return result
    
    def discover_and_check_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Main method to discover and check endpoints for all APIs in scan_id"""
        # First, get the access token for this scan_id
        self.access_token = self.get_access_token_by_scan_id(scan_id)
        if self.access_token:
            logger.info(f"Found access token for scan_id: {scan_id}")
        else:
            logger.warning(f"No access token found for scan_id: {scan_id}. Proceeding without authentication.")
        
        apis = self.get_apis_by_scan_id(scan_id)
        all_results = []
        
        for api in apis:
            logger.info(f"Checking API: {api['name']} - {api['url']}")
            
            # Collect all endpoints to check
            endpoints_to_check = []
            
            # Add common endpoints
            for category, paths in self.COMMON_ENDPOINTS.items():
                for path in paths:
                    endpoints_to_check.append((path, category))
            
            # Add AI-suggested endpoints
            ai_suggested = self.discover_endpoints_with_ai(api)
            for path in ai_suggested:
                category = self.categorize_endpoint(path)
                endpoints_to_check.append((path, category))
            
            # Remove duplicates
            endpoints_to_check = list(set(endpoints_to_check))
            
            # Check each endpoint
            for endpoint_path, category in endpoints_to_check:
                check_result = self.check_endpoint(api['url'], endpoint_path)
                
                result = {
                    'scan_id': scan_id,
                    'api_id': str(api['id']),
                    'api_name': api['name'],
                    'base_url': api['url'],
                    'endpoint_type': category,
                    **check_result
                }
                
                all_results.append(result)
                
                # Log accessible endpoints
                if result['is_accessible']:
                    auth_status = "with auth" if result.get('auth_used') else "without auth"
                    logger.info(f"Found accessible {category} endpoint ({auth_status}): {check_result['endpoint_url']}")
        
        return all_results