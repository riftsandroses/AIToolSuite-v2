import requests
import time
import logging
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class AdminPanelScanner:
    def __init__(self, timeout=10, max_workers=10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = self._create_session()
        
        # Common admin panel paths
        self.admin_paths = [
            '/admin/',
            '/admin',
            '/administrator/',
            '/administrator',
            '/wp-admin/',
            '/wp-admin',
            '/admin.php',
            '/administrator.php',
            '/login.php',
            '/login/',
            '/dashboard/',
            '/dashboard',
            '/control/',
            '/control',
            '/manage/',
            '/manage',
            '/backend/',
            '/backend',
            '/cpanel/',
            '/cpanel',
            '/admin-panel/',
            '/admin-panel',
        ]
        
    def _create_session(self):
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers to mimic a real browser
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
        
    def _is_admin_panel(self, url, response):
        """Check if the response indicates an admin panel"""
        content = response.text.lower()
        
        # Common admin panel indicators
        admin_indicators = [
            'admin login',
            'administrator login',
            'dashboard',
            'admin panel',
            'login to continue',
            'username',
            'password',
            'sign in',
            'log in',
            'authentication required',
            'django administration',
            'wordpress admin',
            'cpanel',
            'control panel',
        ]
        
        # Check for admin panel indicators in content
        for indicator in admin_indicators:
            if indicator in content:
                return True
                
        # Check URL patterns
        if any(path in url.lower() for path in ['/admin', '/login', '/dashboard', '/wp-admin']):
            return True
            
        return False
        
    def _determine_admin_panel_type(self, url, response):
        """Determine the type of admin panel"""
        content = response.text.lower()
        
        if 'django administration' in content:
            return 'Django Admin'
        elif 'wordpress' in content or 'wp-admin' in url:
            return 'WordPress Admin'
        elif 'cpanel' in content or 'cpanel' in url:
            return 'cPanel'
        elif 'phpmyadmin' in content:
            return 'phpMyAdmin'
        elif 'admin panel' in content:
            return 'Generic Admin Panel'
        elif 'login' in content and ('username' in content or 'password' in content):
            return 'Login Panel'
        else:
            return 'Unknown'
            
    def _check_admin_panel(self, base_url, admin_path):
        """Check if an admin panel exists at the given path"""
        try:
            # Construct the full URL
            if not base_url.endswith('/') and not admin_path.startswith('/'):
                full_url = f"{base_url}/{admin_path}"
            else:
                full_url = urljoin(base_url, admin_path)
                
            start_time = time.time()
            response = self.session.get(full_url, timeout=self.timeout, allow_redirects=True)
            response_time = time.time() - start_time
            
            # Consider 2xx and 3xx as potentially valid (some admin panels redirect to login)
            if response.status_code < 400:
                is_admin = self._is_admin_panel(full_url, response)
                if is_admin:
                    admin_type = self._determine_admin_panel_type(full_url, response)
                    return {
                        'url': full_url,
                        'status_code': response.status_code,
                        'is_accessible': True,
                        'response_time': response_time,
                        'admin_panel_type': admin_type,
                        'error_message': None
                    }
            
            return {
                'url': full_url,
                'status_code': response.status_code,
                'is_accessible': False,
                'response_time': response_time,
                'admin_panel_type': None,
                'error_message': f"Status code: {response.status_code}"
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'url': full_url,
                'status_code': None,
                'is_accessible': False,
                'response_time': None,
                'admin_panel_type': None,
                'error_message': str(e)
            }
            
    def scan_url(self, api_url):
        """Scan a single API URL for admin panels"""
        try:
            parsed_url = urlparse(api_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            results = []
            
            # Use ThreadPoolExecutor for concurrent requests
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.admin_paths))) as executor:
                future_to_path = {
                    executor.submit(self._check_admin_panel, base_url, path): path 
                    for path in self.admin_paths
                }
                
                for future in as_completed(future_to_path):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error checking admin panel: {e}")
                        
            return results
            
        except Exception as e:
            logger.error(f"Error scanning URL {api_url}: {e}")
            return []
