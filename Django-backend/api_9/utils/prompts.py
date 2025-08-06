# api_9/utils.py
import openai
import subprocess
import re
import json
import os
from urllib.parse import urlparse, urljoin
from django.conf import settings

class EndpointDiscoveryService:
    def __init__(self):
        self.openai_client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
    
    def get_truncated_url_from_chatgpt(self, url):
        """
        Use ChatGPT to get a truncated base URL for feroxbuster scanning
        """
        try:
            prompt = f"""
            Given this URL: {url}
            
            Please return only the base URL that would be suitable for directory/endpoint scanning.
            For example:
            - https://api.example.com/v1/users/123/profile -> https://api.example.com/v1/
            - http://example.com/api/auth/login -> http://example.com/api/
            - https://service.domain.com/identity/api/token -> https://service.domain.com/identity/api/
            
            Return only the truncated URL, nothing else.
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that extracts base URLs for API scanning. Return only the base URL."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.1
            )
            
            truncated_url = response.choices[0].message.content.strip()
            
            # Validate the URL
            parsed = urlparse(truncated_url)
            if parsed.scheme and parsed.netloc:
                return truncated_url
            else:
                # Fallback: create base URL manually
                original_parsed = urlparse(url)
                return f"{original_parsed.scheme}://{original_parsed.netloc}/"
                
        except Exception as e:
            print(f"Error getting truncated URL from ChatGPT: {e}")
            # Fallback: create base URL manually
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}/"
    
    def run_feroxbuster(self, base_url, jwt_token):
        """
        Run feroxbuster as subprocess to discover endpoints
        """
        try:
            # Use the custom wordlist from api_9/wordlist/
            wordlist_path = os.path.join(settings.BASE_DIR, 'api_9', 'wordlist', 'api-endpoints.txt')
            if not os.path.exists(wordlist_path):
                print(f"Wordlist not found: {wordlist_path}")
                return []

            # Prepare feroxbuster command
            cmd = [
                'feroxbuster',
                '-u', base_url,
                '-w', wordlist_path,
                '-H', f'Authorization: Bearer {jwt_token}',
                '--json',
                '-t', '75',  # 75 threads
                '--depth', '3',
                '--filter-status', '404',
                '--silent'
            ]

            # Run feroxbuster
            logger.info(f"Starting feroxbuster with command: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            logger.info(f"Feroxbuster process started with PID: {process.pid}")

            try:
                stdout, stderr = process.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                process.kill()
                print("Feroxbuster timeout")
                return []

            if process.returncode != 0:
                print(f"Feroxbuster error: {stderr}")
                return []

            # Parse JSON output
            endpoints = []
            for line in stdout.strip().split('\n'):
                if line.strip():
                    try:
                        result = json.loads(line)
                        if result.get('type') == 'response':
                            endpoint_url = result.get('url', '')
                            status_code = result.get('status', 0)
                            method = result.get('method', 'GET')

                            if endpoint_url and status_code < 400:
                                endpoints.append({
                                    'url': endpoint_url,
                                    'status_code': status_code,
                                    'method': method
                                })
                    except json.JSONDecodeError:
                        continue

            return endpoints

        except Exception as e:
            print(f"Error running feroxbuster: {e}")
            return []

    def extract_endpoints_from_output(self, output):
        """
        Extract endpoint URLs from feroxbuster output (fallback for non-JSON output)
        """
        endpoints = []
        lines = output.strip().split('\n')
        
        for line in lines:
            # Look for HTTP status codes and URLs
            match = re.search(r'(\d{3})\s+.*?(https?://[^\s]+)', line)
            if match:
                status_code = int(match.group(1))
                url = match.group(2)
                
                if status_code < 400:  # Only include successful responses
                    endpoints.append({
                        'url': url,
                        'status_code': status_code,
                        'method': 'GET'  # Default method
                    })
        
        return endpoints