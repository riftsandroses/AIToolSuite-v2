import requests
import json
import subprocess
import tempfile
import os
import shutil
from urllib.parse import urlparse, parse_qs, urlencode
from django.db import connection
from django.conf import settings
from typing import List, Dict, Any
import logging
import re

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self, lm_studio_url="http://localhost:1234/v1/chat/completions"):
        self.lm_studio_url = lm_studio_url
    
    #Improved System Prompt
    IMPROVED_SYSTEM_MESSAGE = """You are a cybersecurity expert specializing in API security and SQL injection detection.

Your task is to identify APIs that could potentially be vulnerable to SQL injection attacks.

Key principles:
1. SQL injection occurs when user input is incorporated into SQL queries without proper sanitization
2. While modern frameworks often provide protection, vulnerabilities still exist in real-world applications
3. Parameters that interact with databases should be flagged for testing
4. Focus on identifying APIs that warrant security testing rather than definitive vulnerability assessment

Balance thoroughness with accuracy - flag APIs that have reasonable potential for SQL injection vulnerabilities."""

    def analyze_apis_for_sql_injection(self, apis: List[Dict]) -> List[str]:
        """
        Send APIs to LLM for SQL injection vulnerability analysis
        Returns list of API IDs that are potentially vulnerable
        """
        if not apis:
            return []
        
        logger.info(f"Analyzing {len(apis)} APIs for SQL injection vulnerabilities")
        
        prompt = self._create_analysis_prompt(apis)
        
        payload = {
            "model": "phi-3-mini-4k-instruct",
            "messages": [
                {
                    "role": "system",
                    "content": self.IMPROVED_SYSTEM_MESSAGE
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
                timeout=120  # Reduced timeout
            )
            response.raise_for_status()
            
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # Extract JSON from response
            vulnerable_ids = self._parse_llm_response(content)
            logger.info(f"LLM identified {len(vulnerable_ids)} potentially vulnerable APIs")
            return vulnerable_ids
            
        except requests.exceptions.Timeout:
            logger.error("LLM request timed out")
            return []
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to LLM Studio. Make sure it's running on the correct port.")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with LLM: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error with LLM: {str(e)}")
            return []
    
    def _create_analysis_prompt(self, apis: List[Dict]) -> str:
        """Create a balanced prompt for the LLM to analyze APIs"""
        prompt = """You are a cybersecurity expert specializing in API security and SQL injection detection.

    ANALYSIS APPROACH:
    - Flag APIs that have reasonable potential for SQL injection vulnerabilities
    - Consider both obvious and subtle indicators of database interaction
    - Balance thoroughness with accuracy to catch real vulnerabilities

    VULNERABILITY INDICATORS - Flag APIs that show these patterns:

    PRIMARY INDICATORS (Strong candidates for flagging):
    1. Database-related parameters: id, user_id, product_id, search, query, filter, where, order_by, sort_by, limit, offset
    2. CRUD endpoints with parameters: /users/{id}, /products/{id}, /api/data/{id}
    3. Search and filtering functionality: /search, /filter, /find, /list with query parameters
    4. Dynamic query construction patterns: endpoints with multiple query parameters
    5. Sorting and pagination: APIs with sort, order, page, limit parameters
    6. Data retrieval with user input: /api/users/search?name=, /api/products/filter?category=

    SECONDARY INDICATORS (Consider for flagging):
    1. Numeric parameters in URL paths or query strings
    2. Text input parameters that could be used in database queries
    3. APIs with complex parameter combinations
    4. Endpoints suggesting database operations: /get, /find, /retrieve, /lookup
    5. Parameters with database-like names: table, column, field, record

    PATTERNS TO GENERALLY EXCLUDE:
    1. Static endpoints with no parameters: /api/health, /api/version, /api/status
    2. File operations: /upload, /download, /file
    3. Authentication without data queries: /login, /logout, /token, /auth
    4. Configuration endpoints: /config, /settings (unless they have query parameters)
    5. Pure metadata endpoints: /schema, /docs, /help

    EVALUATION GUIDELINES:
    1. If an API has user-controllable parameters that could reach a database, consider flagging it
    2. Multiple parameters increase likelihood of vulnerability
    3. Common database operation patterns should be flagged
    4. When uncertain about borderline cases, lean toward flagging for security testing
    5. Consider the HTTP method - POST/PUT with data parameters are often worth testing

    APIs to analyze:

    """
        
        for api in apis:
            # Parse URL to extract query parameters and path structure
            parsed_url = urlparse(api['url'])
            query_params = parse_qs(parsed_url.query)
            path_segments = [seg for seg in parsed_url.path.split('/') if seg]
            
            # Extract potential path parameters (like /users/{id})
            path_params = []
            for i, segment in enumerate(path_segments):
                if i < len(path_segments) - 1:
                    next_segment = path_segments[i + 1]
                    # Check if next segment could be a parameter (numeric or placeholder-like)
                    if (next_segment.isdigit() or 
                        '{' in next_segment or 
                        next_segment.startswith(':') or
                        len(next_segment) > 10):  # Could be an ID
                        path_params.append(f"{segment}_id")
            
            # Analyze body parameters if present
            body_params = []
            body_content = api.get('body', {})
            if isinstance(body_content, dict):
                body_params = list(body_content.keys())
            elif isinstance(body_content, str):
                try:
                    parsed_body = json.loads(body_content)
                    if isinstance(parsed_body, dict):
                        body_params = list(parsed_body.keys())
                except:
                    pass
            
            prompt += f"""
    API ID: {api['id']}
    URL: {api['url']}
    Method: {api.get('method', 'GET')}
    Path Structure: /{'/'.join(path_segments)}
    Query Parameters: {list(query_params.keys()) if query_params else 'None'}
    Path Parameters: {path_params if path_params else 'None'}
    Body Parameters: {body_params if body_params else 'None'}
    Content-Type: {api.get('headers', {}).get('Content-Type', 'Not specified')}
    ---
    """
        
        prompt += """
    RESPONSE FORMAT:
    Return ONLY a JSON array of API IDs that have reasonable potential for SQL injection vulnerability.
    Include APIs that warrant security testing based on the indicators above.
    Focus on APIs with user-controllable parameters that could interact with databases.

    Example: ["api_id_1", "api_id_3", "api_id_7"]

    If no APIs meet the criteria, return an empty array: []
    """
        
        return prompt
    
    def _parse_llm_response(self, content: str) -> List[str]:
        """Parse LLM response to extract API IDs"""
        try:
            # Clean the content
            content = content.strip()
            logger.debug(f"LLM raw response: {content}")
            
            # Try to find JSON array in the response
            json_match = re.search(r'\[([^\]]*)\]', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                logger.debug(f"Extracted JSON: {json_str}")
                result = json.loads(json_str)
                # Convert all IDs to strings for consistency
                return [str(id_val) for id_val in result]
            
            # If no array found, maybe it's just the array
            if content.startswith('[') and content.endswith(']'):
                result = json.loads(content)
                return [str(id_val) for id_val in result]
                
            logger.warning(f"No valid JSON array found in LLM response: {content}")
            return []
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}, Content: {content}")
            return []
        except Exception as e:
            logger.error(f"Error parsing LLM response: {str(e)}")
            return []

class ChatGPTService:
    def __init__(self, api_key=None):
        self.api_key = api_key or getattr(settings, 'OPENAI_API_KEY', None)
        self.api_url = "https://api.openai.com/v1/chat/completions"
        
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY in settings.")
    
    #Improved System Prompt
    IMPROVED_SYSTEM_MESSAGE = """You are a cybersecurity expert specializing in API security and SQL injection detection.

Your task is to identify APIs that could potentially be vulnerable to SQL injection attacks.

Key principles:
1. SQL injection occurs when user input is incorporated into SQL queries without proper sanitization
2. While modern frameworks often provide protection, vulnerabilities still exist in real-world applications
3. Parameters that interact with databases should be flagged for testing
4. Focus on identifying APIs that warrant security testing rather than definitive vulnerability assessment

Balance thoroughness with accuracy - flag APIs that have reasonable potential for SQL injection vulnerabilities."""

    
    def analyze_apis_for_sql_injection(self, apis: List[Dict]) -> List[str]:
        """
        Send APIs to ChatGPT for SQL injection vulnerability analysis
        Returns list of API IDs that are potentially vulnerable
        """
        if not apis:
            return []
        
        logger.info(f"Analyzing {len(apis)} APIs for SQL injection vulnerabilities")
        
        prompt = self._create_analysis_prompt(apis)

        payload = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "system",
                    "content": self.IMPROVED_SYSTEM_MESSAGE
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 1000
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # Extract JSON from response
            vulnerable_ids = self._parse_llm_response(content)
            logger.info(f"ChatGPT identified {len(vulnerable_ids)} potentially vulnerable APIs")
            return vulnerable_ids
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with ChatGPT API: {str(e)}")
            if hasattr(e.response, 'text'):
                logger.error(f"Response content: {e.response.text}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error with ChatGPT API: {str(e)}")
            return []
    
    def _create_analysis_prompt(self, apis: List[Dict]) -> str:
        """Create a balanced prompt for the LLM to analyze APIs"""
        prompt = """You are a cybersecurity expert specializing in API security and SQL injection detection.

    ANALYSIS APPROACH:
    - Flag APIs that have reasonable potential for SQL injection vulnerabilities
    - Consider both obvious and subtle indicators of database interaction
    - Balance thoroughness with accuracy to catch real vulnerabilities

    VULNERABILITY INDICATORS - Flag APIs that show these patterns:

    PRIMARY INDICATORS (Strong candidates for flagging):
    1. Database-related parameters: id, user_id, product_id, search, query, filter, where, order_by, sort_by, limit, offset
    2. CRUD endpoints with parameters: /users/{id}, /products/{id}, /api/data/{id}
    3. Search and filtering functionality: /search, /filter, /find, /list with query parameters
    4. Dynamic query construction patterns: endpoints with multiple query parameters
    5. Sorting and pagination: APIs with sort, order, page, limit parameters
    6. Data retrieval with user input: /api/users/search?name=, /api/products/filter?category=

    SECONDARY INDICATORS (Consider for flagging):
    1. Numeric parameters in URL paths or query strings
    2. Text input parameters that could be used in database queries
    3. APIs with complex parameter combinations
    4. Endpoints suggesting database operations: /get, /find, /retrieve, /lookup
    5. Parameters with database-like names: table, column, field, record

    PATTERNS TO GENERALLY EXCLUDE:
    1. Static endpoints with no parameters: /api/health, /api/version, /api/status
    2. File operations: /upload, /download, /file
    3. Authentication without data queries: /login, /logout, /token, /auth
    4. Configuration endpoints: /config, /settings (unless they have query parameters)
    5. Pure metadata endpoints: /schema, /docs, /help

    EVALUATION GUIDELINES:
    1. If an API has user-controllable parameters that could reach a database, consider flagging it
    2. Multiple parameters increase likelihood of vulnerability
    3. Common database operation patterns should be flagged
    4. When uncertain about borderline cases, lean toward flagging for security testing
    5. Consider the HTTP method - POST/PUT with data parameters are often worth testing

    APIs to analyze:

    """
        
        for api in apis:
            # Parse URL to extract query parameters and path structure
            parsed_url = urlparse(api['url'])
            query_params = parse_qs(parsed_url.query)
            path_segments = [seg for seg in parsed_url.path.split('/') if seg]
            
            # Extract potential path parameters (like /users/{id})
            path_params = []
            for i, segment in enumerate(path_segments):
                if i < len(path_segments) - 1:
                    next_segment = path_segments[i + 1]
                    # Check if next segment could be a parameter (numeric or placeholder-like)
                    if (next_segment.isdigit() or 
                        '{' in next_segment or 
                        next_segment.startswith(':') or
                        len(next_segment) > 10):  # Could be an ID
                        path_params.append(f"{segment}_id")
            
            # Analyze body parameters if present
            body_params = []
            body_content = api.get('body', {})
            if isinstance(body_content, dict):
                body_params = list(body_content.keys())
            elif isinstance(body_content, str):
                try:
                    parsed_body = json.loads(body_content)
                    if isinstance(parsed_body, dict):
                        body_params = list(parsed_body.keys())
                except:
                    pass
            
            prompt += f"""
    API ID: {api['id']}
    URL: {api['url']}
    Method: {api.get('method', 'GET')}
    Path Structure: /{'/'.join(path_segments)}
    Query Parameters: {list(query_params.keys()) if query_params else 'None'}
    Path Parameters: {path_params if path_params else 'None'}
    Body Parameters: {body_params if body_params else 'None'}
    Content-Type: {api.get('headers', {}).get('Content-Type', 'Not specified')}
    ---
    """
        
        prompt += """
    RESPONSE FORMAT:
    Return ONLY a JSON array of API IDs that have reasonable potential for SQL injection vulnerability.
    Include APIs that warrant security testing based on the indicators above.
    Focus on APIs with user-controllable parameters that could interact with databases.

    Example: ["api_id_1", "api_id_3", "api_id_7"]

    If no APIs meet the criteria, return an empty array: []
    """
        
        return prompt
    
    def _parse_llm_response(self, content: str) -> List[str]:
        """Parse ChatGPT response to extract API IDs"""
        try:
            # Clean the content first
            content = content.strip()
            logger.debug(f"ChatGPT raw response: {content}")
            
            # Remove markdown code blocks if present
            if content.startswith('```') and content.endswith('```'):
                lines = content.split('\n')
                content = '\n'.join(lines[1:-1])
            
            # Try to find JSON array in the response
            json_match = re.search(r'\[([^\]]*)\]', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                logger.debug(f"Extracted JSON: {json_str}")
                result = json.loads(json_str)
                # Convert all IDs to strings for consistency
                return [str(id_val) for id_val in result]
            
            # If no JSON array found, try to parse the entire content as JSON
            if content.startswith('[') and content.endswith(']'):
                result = json.loads(content)
                return [str(id_val) for id_val in result]
                
            logger.warning(f"No valid JSON array found in ChatGPT response: {content}")
            return []
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}, Content: {content}")
            return []
        except Exception as e:
            logger.error(f"Error parsing ChatGPT response: {str(e)}")
            return []

class SQLMapService:
    def __init__(self):
        self.sqlmap_path = self._find_sqlmap_path()

    def _find_sqlmap_path(self):
        possible_paths = [
            "sqlmap",
            "sqlmap.py",
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/homebrew/bin/sqlmap",
            os.path.expanduser("~/.local/bin/sqlmap"),
            "/usr/share/sqlmap/sqlmap.py",
            "python3 -m sqlmap",
        ]

        for path in possible_paths:
            if path.startswith("python3 -m"):
                try:
                    result = subprocess.run([
                        "python3", "-c", "import sqlmapapi"
                    ], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        return "python3 -m sqlmap"
                except:
                    continue
            else:
                expanded_path = os.path.expanduser(path)
                if os.path.isfile(expanded_path):
                    return expanded_path
                elif shutil.which(path):
                    return path

        raise RuntimeError("SQLMap not found. Please install sqlmap and ensure it's in your PATH.")

    def test_sql_injection(self, api_data: Dict, token: str) -> Dict:
        try:
            output_dir = tempfile.mkdtemp(prefix='sqlmap_')
            test_data = self._prepare_api_for_testing(api_data)
            if not test_data:
                return {"vulnerable": False, "error": "No testable parameters found"}

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                request_file = f.name
                self._create_request_file(f, test_data, token)

            cmd = self._build_sqlmap_command(request_file, output_dir)
            logger.info(f"Running SQLMap command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )

            parsed_data = self._extract_sqlmap_dump(output_dir)

            try:
                os.unlink(request_file)
            except:
                pass

            return self._parse_sqlmap_output(result.stdout, result.stderr, result.returncode, parsed_data, output_dir)

        except subprocess.TimeoutExpired:
            logger.error("SQLMap timed out")
            return {"vulnerable": False, "error": "SQLMap timed out"}
        except Exception as e:
            logger.error(f"SQLMap execution failed: {str(e)}")
            return {"vulnerable": False, "error": str(e)}

    def _prepare_api_for_testing(self, api_data: Dict) -> Dict:
        url = api_data['url']
        method = api_data.get('method', 'GET').upper()
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if not query_params and method == 'GET':
            url += '&test=1' if '?' in url else '?test=1'

        body = api_data.get('body', {})
        if method == 'POST' and not body:
            body = {"test": "1"}

        return {
            'url': url,
            'method': method,
            'headers': api_data.get('headers', {}),
            'body': body
        }

    def _build_sqlmap_command(self, request_file: str, output_dir: str) -> List[str]:
        if self.sqlmap_path.startswith("python3 -m"):
            cmd = ["python3", "-m", "sqlmap"]
        else:
            cmd = [self.sqlmap_path]

        cmd.extend([
            "-r", request_file,
            "--batch",
            "--level=5",
            "--risk=3",
            "--timeout=30",
            "--retries=2",
            f"--output-dir={output_dir}",
            "--flush-session",
            "--fresh-queries",
            "--crawl=0",
            "--random-agent",
            "--technique=BEUSTQ",
            "--threads=1",
            "--no-cast",
            "--dbs",
            "--tables",
            "--columns",
            "--dump",
            "--delay=0.033",
            "-v", "3", 
        ])

        return cmd

    def _create_request_file(self, file_handle, api_data: Dict, token: str):
        method = api_data.get('method', 'GET').upper()
        url = api_data['url']
        headers = api_data.get('headers', {}).copy()

        # Fix body if it's in {"raw": "...", "mode": "raw"} format
        body_raw = api_data.get('body', '')
        if isinstance(body_raw, dict) and body_raw.get("mode") == "raw" and "raw" in body_raw:
            try:
                body = json.loads(body_raw["raw"])
            except json.JSONDecodeError:
                body = body_raw["raw"]  # fallback as-is
        else:
            body = body_raw

        # Inject JWT token from scan DB
        if token:
            headers['Authorization'] = f"Bearer {token}"

        headers.setdefault('User-Agent', 'Mozilla/5.0 (compatible; SQLMap)')
        headers.setdefault('Accept', '*/*')

        parsed_url = urlparse(url)
        path_and_query = parsed_url.path + ('?' + parsed_url.query if parsed_url.query else '')

        file_handle.write(f"{method} {path_and_query} HTTP/1.1\n")
        file_handle.write(f"Host: {parsed_url.netloc}\n")
        for key, value in headers.items():
            file_handle.write(f"{key}: {value}\n")

        if body and method in ['POST', 'PUT', 'PATCH']:
            body_str = json.dumps(body) if isinstance(body, dict) else str(body)
            file_handle.write(f"Content-Length: {len(body_str)}\n")
            file_handle.write("\n")
            file_handle.write(body_str)
        else:
            file_handle.write("\n")

    def _extract_sqlmap_dump(self, output_dir: str) -> str:
        dump_dir = os.path.join(output_dir, "dump")
        parsed_output = []
        if os.path.isdir(dump_dir):
            for root, dirs, files in os.walk(dump_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        parsed_output.append(f"File: {file}\n{content}\n")
                    except Exception as e:
                        logger.error(f"Error reading dump file {file}: {str(e)}")
        return "\n".join(parsed_output)

    def _parse_sqlmap_output(self, stdout: str, stderr: str, returncode: int, dump_data: str, output_dir: str) -> Dict:
        result = {
            "vulnerable": False,
            "details": "",
            "severity": "info",
            "sqlmap_output": stdout if stdout else "",
            "dumped_data": dump_data,
            "dumped_files_dir": output_dir
        }

        patterns = [
            r"parameter '.+?' is vulnerable",
            r"parameter '.+?' appears to be '.+?' injectable",
            r"\[INFO\] .+? parameter '.+?' is '.+?' injectable",
            r"sqlmap identified the following injection point",
            r"Type: .+",
            r"Title: .+",
            r"Payload: .+"
        ]

        details = []
        for pattern in patterns:
            matches = re.finditer(pattern, stdout, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                result["vulnerable"] = True
                result["severity"] = "high"
                details.append(match.group(0))

        if result["vulnerable"]:
            result["details"] = "; ".join(details[:5])
        elif "all tested parameters do not appear to be injectable" in stdout.lower():
            result["details"] = "All parameters appear safe"
        elif "no parameter(s) found for testing" in stdout.lower():
            result["details"] = "No testable parameters found"
        elif returncode != 0 and stderr:
            result["details"] = f"SQLMap error: {stderr[:200]}"
        else:
            result["details"] = "SQLMap analysis completed"

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
            results = []
            
            for row in cursor.fetchall():
                api_dict = dict(zip(columns, row))
                
                # Parse JSON fields safely
                try:
                    if api_dict.get('headers') and isinstance(api_dict['headers'], str):
                        api_dict['headers'] = json.loads(api_dict['headers'])
                except json.JSONDecodeError:
                    api_dict['headers'] = {}
                
                try:
                    if api_dict.get('body') and isinstance(api_dict['body'], str):
                        api_dict['body'] = json.loads(api_dict['body'])
                except json.JSONDecodeError:
                    api_dict['body'] = {}
                
                # Ensure headers and body are dictionaries
                if not isinstance(api_dict.get('headers'), dict):
                    api_dict['headers'] = {}
                if not isinstance(api_dict.get('body'), dict):
                    api_dict['body'] = {}
                
                results.append(api_dict)
            
            return results
    
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