# services.py - Updated with PATH fixes
import openai
import subprocess
import json
import logging
import shutil
import os
from urllib.parse import urlparse
from django.conf import settings
from api_orch.models import PostmanAPI
from .models import SubdomainDiscovery

logger = logging.getLogger(__name__)

from openai import OpenAI

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