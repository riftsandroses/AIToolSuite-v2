import requests
import json
import subprocess
import tempfile
import os
from django.db import connection
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self, lm_studio_url="http://localhost:1234/v1/chat/completions"):
        self.lm_studio_url = lm_studio_url
    
    def analyze_apis_for_sql_injection(self, apis: List[Dict]) -> List[str]:
        """
        Send APIs to LLM for SQL injection vulnerability analysis
        Returns list of API IDs that are potentially vulnerable
        """
        prompt = self._create_analysis_prompt(apis)
        
        payload = {
            "model": "local-model",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in API security. Analyze the provided APIs and identify which ones might be vulnerable to SQL injection attacks. Return only the API IDs as a JSON array."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 1000
        }
        
        try:
            response = requests.post(
                self.lm_studio_url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # Extract JSON from response
            vulnerable_ids = self._parse_llm_response(content)
            logger.info(f"LLM identified {len(vulnerable_ids)} potentially vulnerable APIs")
            return vulnerable_ids
            
        except Exception as e:
            logger.error(f"Error communicating with LLM: {str(e)}")
            return []
    
    def _create_analysis_prompt(self, apis: List[Dict]) -> str:
        """Create a prompt for the LLM to analyze APIs"""
        prompt = """Analyze the following APIs for potential SQL injection vulnerabilities. 
        Look for:
        1. APIs with parameters that might be passed to database queries
        2. GET/POST parameters that could contain user input
        3. Endpoints that suggest database operations (search, filter, id lookups)
        4. Missing parameter validation indicators
        
        APIs to analyze:
        
        """
        
        for api in apis:
            prompt += f"""
API ID: {api['id']}
URL: {api['url']}
Method: {api.get('method', 'GET')}
Headers: {api.get('headers', {})}
Body: {api.get('body', {})}
---
"""
        
        prompt += "\nReturn only a JSON array of API IDs that are potentially vulnerable to SQL injection: [\"id1\", \"id2\", ...]"
        return prompt
    
    def _parse_llm_response(self, content: str) -> List[str]:
        """Parse LLM response to extract API IDs"""
        try:
            # Try to find JSON array in the response
            import re
            json_match = re.search(r'\[.*?\]', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return []
        except:
            return []

class SQLMapService:
    def __init__(self):
        self.sqlmap_path = "sqlmap"  # Assumes sqlmap is in PATH
    
    def test_sql_injection(self, api_data: Dict, token: str) -> Dict:
        """
        Test an API for SQL injection using sqlmap
        """
        try:
            # Create temporary files for sqlmap
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                request_file = f.name
                self._create_request_file(f, api_data, token)
            
            # Run sqlmap
            cmd = [
                self.sqlmap_path,
                "-r", request_file,
                "--batch",
                "--level=3",
                "--risk=2",
                "--timeout=30",
                "--retries=2",
                "--output-dir=/tmp/sqlmap_output",
                "--format=JSON"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Clean up
            os.unlink(request_file)
            
            return self._parse_sqlmap_output(result.stdout, result.stderr, result.returncode)
            
        except Exception as e:
            logger.error(f"Error running sqlmap: {str(e)}")
            return {"vulnerable": False, "error": str(e)}
    
    def _create_request_file(self, file_handle, api_data: Dict, token: str):
        """Create HTTP request file for sqlmap"""
        method = api_data.get('method', 'GET')
        url = api_data['url']
        headers = api_data.get('headers', {})
        body = api_data.get('body', '')
        
        # Add authorization header
        if token:
            headers['Authorization'] = f"Bearer {token}"
        
        # Write request
        file_handle.write(f"{method} {url} HTTP/1.1\n")
        file_handle.write("Host: localhost\n")  # Adjust as needed
        
        for key, value in headers.items():
            file_handle.write(f"{key}: {value}\n")
        
        if body:
            file_handle.write(f"Content-Length: {len(body)}\n")
            file_handle.write("\n")
            file_handle.write(body)
        else:
            file_handle.write("\n")
    
    def _parse_sqlmap_output(self, stdout: str, stderr: str, returncode: int) -> Dict:
        """Parse sqlmap output"""
        result = {
            "vulnerable": False,
            "details": "",
            "severity": "info"
        }
        
        if returncode == 0:
            if "is vulnerable" in stdout.lower():
                result["vulnerable"] = True
                result["severity"] = "high"
                result["details"] = "SQL injection vulnerability detected"
            else:
                result["details"] = "No SQL injection vulnerability detected"
        else:
            result["details"] = f"SQLMap error: {stderr}"
            
        return result

class DatabaseService:
    @staticmethod
    def get_scan_apis(scan_id: str) -> List[Dict]:
        """Get APIs for a specific scan ID"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT p.id, p.url, p.method, p.headers, p.body, p.authorization
                FROM api_orch_postmanapi p
                INNER JOIN api_orch_scan s ON p.scan_id = s.id
                WHERE s.id = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    @staticmethod
    def get_scan_token(scan_id: str) -> str:
        """Get JWT token for scan"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT access_token
                FROM api_orch_scantokens
                WHERE scan_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else ""
    
    @staticmethod
    def scan_exists(scan_id: str) -> bool:
        """Check if scan exists"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 1 FROM api_orch_scan WHERE id = %s
            """, [scan_id])
            return cursor.fetchone() is not None