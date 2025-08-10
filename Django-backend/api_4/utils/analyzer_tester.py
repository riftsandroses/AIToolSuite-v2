import json
import subprocess
import requests
import openai
from typing import List, Dict, Any, Optional
from django.conf import settings
import logging


logger = logging.getLogger(__name__)


class ChatGPTAnalyzer:
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
    
    def analyze_apis_for_pagination(self, apis_batch: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a batch of APIs to identify potential unbounded pagination vulnerabilities
        """
        apis_summary = []
        for api in apis_batch:
            api_info = {
                'url': api.get('url', ''),
                'method': api.get('method', 'GET'),
                'query_params': api.get('query_params', {}),
                'body': api.get('body', {}),
                'headers': api.get('headers', {})
            }
            apis_summary.append(api_info)
        
        prompt = f"""
        Analyze the following APIs for potential unbounded pagination vulnerabilities. 
        Look for parameters that could control pagination such as:
        - 'limit', 'page_size', 'per_page', 'count', 'size'
        - 'page', 'offset', 'skip', 'start'
        - Any parameter that might control the amount of data returned
        
        For each API that has potential pagination parameters, return a JSON object with:
        - "vulnerable_apis": array of objects with "url" and "parameters"
        - "analysis_summary": string summary
        
        The parameters array should include:
        - "name": parameter name
        - "location": where it's found (query_params, body, headers)
        - "test_value": number to test (like 99999)
        - "original_value": original value if exists
        
        APIs to analyze:
        {json.dumps(apis_summary, indent=2)}
        
        Respond ONLY with valid JSON in this exact format:
        {{
            "vulnerable_apis": [
                {{
                    "url": "api_url",
                    "parameters": [
                        {{
                            "name": "parameter_name",
                            "location": "query_params|body|headers",
                            "test_value": 99999,
                            "original_value": "original_value_if_exists"
                        }}
                    ]
                }}
            ],
            "analysis_summary": "Brief summary of findings"
        }}
        """
        
        logger.info(f"Sending {len(apis_batch)} APIs to ChatGPT for analysis")
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # Changed to valid model name
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in API vulnerability assessment. Respond with ONLY valid JSON in the specified format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={ "type": "json_object" }  # Request JSON response
            )
            
            result = response.choices[0].message.content
            logger.debug(f"ChatGPT raw response: {result}")
            
            try:
                parsed_result = json.loads(result)
                logger.info("ChatGPT analysis completed successfully")
                return parsed_result
            except json.JSONDecodeError as je:
                logger.error(f"Failed to parse ChatGPT response: {je}\nResponse was: {result}")
                return {
                    "error": "Invalid JSON response from ChatGPT",
                    "vulnerable_apis": [],
                    "analysis_summary": "Analysis failed - invalid response format"
                }
                
        except Exception as e:
            logger.error(f"ChatGPT analysis failed: {str(e)}")
            return {
                "error": str(e),
                "vulnerable_apis": [],
                "analysis_summary": "Analysis failed due to error"
            }

class VulnerabilityTester:
    @staticmethod
    def prepare_curl_command(url: str, method: str, headers: Dict, body: Dict, 
                        query_params: Dict, auth_token: str, 
                        test_param: str, test_value: int, param_location: str) -> str:
        """
        Prepare curl command to test for unbounded pagination
        """
        logger.info(f"Preparing curl command for {method} {url} with parameter {test_param}={test_value} in {param_location}")

        # Prepare headers
        curl_headers = []
        if headers:
            for key, value in headers.items():
                if key.lower() != 'authorization':
                    curl_headers.append(f'-H "{key}: {value}"')
        
        # Add authorization
        if auth_token:
            curl_headers.append(f'-H "Authorization: Bearer {auth_token}"')
        
        # Prepare the test parameters based on location
        test_query_params = query_params.copy() if query_params else {}
        test_body = body.copy() if body else {}
        
        if param_location == 'query_params':
            test_query_params[test_param] = test_value
        elif param_location == 'body':
            if 'raw' in test_body:
                try:
                    raw_data = json.loads(test_body['raw'])
                    raw_data[test_param] = test_value
                    test_body['raw'] = json.dumps(raw_data)
                except:
                    test_body[test_param] = test_value
            else:
                test_body[test_param] = test_value
        
        # Build URL with query parameters - FIXED VERSION
        base_url = url.split('?')[0]  # Get URL without existing query params
        if test_query_params:
            query_string = '&'.join([f"{k}={v}" for k, v in test_query_params.items()])
            test_url = f"{base_url}?{query_string}"
        else:
            test_url = base_url
        
        # Build curl command
        curl_parts = ['curl', '-s', '-w', '"Status: %{http_code}\\nSize: %{size_download}"']
        curl_parts.extend(curl_headers)
        
        if method.upper() != 'GET' and test_body:
            if 'raw' in test_body:
                curl_parts.extend(['-d', f"'{test_body['raw']}'"])
            else:
                curl_parts.extend(['-d', f"'{json.dumps(test_body)}'"])
        
        curl_parts.extend(['-X', method.upper()])
        curl_parts.append(f"'{test_url}'")
        
        curl_command = ' '.join(curl_parts)
        logger.debug(f"Generated curl command: {curl_command}")
        return curl_command
    
    @staticmethod
    def execute_vulnerability_test(curl_command: str) -> Dict[str, Any]:
        """
        Execute the curl command and analyze the response
        """

        logger.info(f"Executing vulnerability test")
        logger.debug(f"Curl command: {curl_command}")

        try:
            logger.info(f"Executing curl command: {curl_command}")
            result = subprocess.run(
                curl_command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            output = result.stdout + result.stderr
            logger.info(f"Curl command executed successfully")
            logger.debug(f"Curl output: {output}")
            
            # Parse status code and size
            status_code = None
            response_size = None
            
            lines = output.split('\n')
            for line in lines:
                if line.startswith('Status: '):
                    try:
                        status_code = int(line.replace('Status: ', '').strip())
                    except:
                        pass
                elif line.startswith('Size: '):
                    try:
                        response_size = int(line.replace('Size: ', '').strip())
                    except:
                        pass
            
            return {
                'success': True,
                'status_code': status_code,
                'response_size': response_size,
                'output': output,
                'error': None
            }
        except subprocess.TimeoutExpired:
            logger.warning("Curl request timed out after 30 seconds")
            return {
                'success': False,
                'status_code': None,
                'response_size': None,
                'output': None,
                'error': 'Request timed out'
            }
        except Exception as e:
            logger.error(f"Curl execution failed: {str(e)}")
            return {
                'success': False,
                'status_code': None,
                'response_size': None,
                'output': None,
                'error': str(e)
            }