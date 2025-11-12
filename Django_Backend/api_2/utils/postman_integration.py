import json
import requests
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class PostmanIntegrationTC1:
    """Integration utility for working with Postman collection data"""
    
    @staticmethod
    def parse_postman_headers(headers_json: str) -> Dict:
        """Parse Postman headers JSON string"""
        try:
            if not headers_json:
                return {}
            
            # Handle both string and dict formats
            if isinstance(headers_json, str):
                headers = json.loads(headers_json)
            else:
                headers = headers_json
                
            # Normalize header names to lowercase
            normalized_headers = {}
            for key, value in headers.items():
                normalized_headers[key.lower()] = value
                
            return normalized_headers
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing headers: {str(e)}")
            return {}
    
    @staticmethod
    def parse_postman_body(body_json: str) -> Dict:
        """Parse Postman body JSON string"""
        try:
            if not body_json:
                return {}
            
            if isinstance(body_json, str):
                body = json.loads(body_json)
            else:
                body = body_json
                
            # Handle different body modes
            if body.get('mode') == 'raw':
                raw_data = body.get('raw', '')
                try:
                    # Try to parse as JSON
                    parsed_raw = json.loads(raw_data)
                    return {
                        'mode': 'raw',
                        'raw': raw_data,
                        'parsed': parsed_raw
                    }
                except json.JSONDecodeError:
                    # Return as plain text
                    return {
                        'mode': 'raw',
                        'raw': raw_data,
                        'parsed': None
                    }
            elif body.get('mode') == 'formdata':
                return {
                    'mode': 'formdata',
                    'formdata': body.get('formdata', [])
                }
            elif body.get('mode') == 'urlencoded':
                return {
                    'mode': 'urlencoded',
                    'urlencoded': body.get('urlencoded', [])
                }
            
            return body
            
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing body: {str(e)}")
            return {}
    
    @staticmethod
    def parse_postman_auth(auth_json: str) -> Dict:
        """Parse Postman authorization JSON string"""
        try:
            if not auth_json:
                return {'type': 'noauth'}
            
            if isinstance(auth_json, str):
                auth = json.loads(auth_json)
            else:
                auth = auth_json
                
            return auth
            
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing authorization: {str(e)}")
            return {'type': 'noauth'}
    
    @staticmethod
    def extract_variables_from_url(url: str) -> List[str]:
        """Extract Postman variables from URL (e.g., {{baseUrl}})"""
        import re
        variables = re.findall(r'\{\{([^}]+)\}\}', url)
        return variables
    
    @staticmethod
    def substitute_variables(text: str, variables: Dict) -> str:
        """Substitute Postman variables in text"""
        if not text or not variables:
            return text
            
        import re
        def replace_var(match):
            var_name = match.group(1)
            return variables.get(var_name, match.group(0))
        
        return re.sub(r'\{\{([^}]+)\}\}', replace_var, text)
    
    @staticmethod
    def convert_to_curl_command(api_data: Dict, variables: Dict = None) -> str:
        """Convert API data to cURL command for testing"""
        method = api_data.get('method', 'GET')
        url = api_data.get('url', '')
        
        # Substitute variables if provided
        if variables:
            url = PostmanIntegrationTC1.substitute_variables(url, variables)
        
        # Build cURL command
        curl_parts = [f"curl -X {method}"]
        
        # Add headers
        headers = PostmanIntegrationTC1.parse_postman_headers(api_data.get('headers', '{}'))
        for key, value in headers.items():
            if variables:
                value = PostmanIntegrationTC1.substitute_variables(value, variables)
            curl_parts.append(f'-H "{key}: {value}"')
        
        # Add authorization
        auth = PostmanIntegrationTC1.parse_postman_auth(api_data.get('authorization', '{}'))
        if auth.get('type') == 'bearer':
            token = auth.get('bearer', [{}])[0].get('value', '')
            if variables:
                token = PostmanIntegrationTC1.substitute_variables(token, variables)
            curl_parts.append(f'-H "Authorization: Bearer {token}"')
        elif auth.get('type') == 'basic':
            # Handle basic auth
            username = auth.get('basic', [{}])[0].get('username', '')
            password = auth.get('basic', [{}])[0].get('password', '')
            if username and password:
                curl_parts.append(f'--user "{username}:{password}"')
        
        # Add body
        body = PostmanIntegrationTC1.parse_postman_body(api_data.get('body', '{}'))
        if body.get('mode') == 'raw' and body.get('raw'):
            raw_data = body['raw']
            if variables:
                raw_data = PostmanIntegrationTC1.substitute_variables(raw_data, variables)
            curl_parts.append(f"--data '{raw_data}'")
        
        # Add URL
        curl_parts.append(f'"{url}"')
        
        return ' \\\n  '.join(curl_parts)
    
    @staticmethod
    def generate_test_scenarios(api_data: Dict) -> List[Dict]:
        """Generate different test scenarios for the API"""
        scenarios = []
        
        base_scenario = {
            'name': api_data.get('name', 'Unknown API'),
            'method': api_data.get('method', 'GET'),
            'url': api_data.get('url', ''),
            'original_headers': PostmanIntegrationTC1.parse_postman_headers(api_data.get('headers', '{}')),
            'original_body': PostmanIntegrationTC1.parse_postman_body(api_data.get('body', '{}')),
            'original_auth': PostmanIntegrationTC1.parse_postman_auth(api_data.get('authorization', '{}'))
        }
        
        # Scenario 1: No authentication
        no_auth_scenario = base_scenario.copy()
        no_auth_scenario['test_name'] = 'No Authentication Test'
        no_auth_scenario['auth'] = {'type': 'noauth'}
        no_auth_scenario['headers'] = {k: v for k, v in base_scenario['original_headers'].items() 
                                     if 'authorization' not in k.lower()}
        scenarios.append(no_auth_scenario)
        
        # Scenario 2: Empty authorization header
        empty_auth_scenario = base_scenario.copy()
        empty_auth_scenario['test_name'] = 'Empty Authorization Header Test'
        empty_auth_scenario['headers'] = base_scenario['original_headers'].copy()
        empty_auth_scenario['headers']['authorization'] = ''
        scenarios.append(empty_auth_scenario)
        
        # Scenario 3: Invalid token format
        invalid_token_scenario = base_scenario.copy()
        invalid_token_scenario['test_name'] = 'Invalid Token Format Test'
        invalid_token_scenario['headers'] = base_scenario['original_headers'].copy()
        invalid_token_scenario['headers']['authorization'] = 'Bearer invalid_token_123'
        scenarios.append(invalid_token_scenario)
        
        # Scenario 4: Missing required headers
        missing_headers_scenario = base_scenario.copy()
        missing_headers_scenario['test_name'] = 'Missing Headers Test'
        missing_headers_scenario['headers'] = {k: v for k, v in base_scenario['original_headers'].items() 
                                             if k.lower() not in ['content-type', 'accept']}
        scenarios.append(missing_headers_scenario)
        
        return scenarios

class PostmanCollectionAnalyzerTC1:
    """Analyzer for Postman collection security patterns"""
    
    @staticmethod
    def analyze_collection_security(apis: List[Dict]) -> Dict:
        """Analyze overall security patterns in the collection"""
        analysis = {
            'total_apis': len(apis),
            'authentication_summary': {
                'no_auth': 0,
                'basic_auth': 0,
                'bearer_token': 0,
                'api_key': 0,
                'oauth': 0,
                'other': 0
            },
            'security_issues': [],
            'recommendations': []
        }
        
        auth_methods = []
        sensitive_endpoints = []
        
        for api in apis:
            # Analyze authentication
            auth = PostmanIntegrationTC1.parse_postman_auth(api.get('authorization', '{}'))
            auth_type = auth.get('type', 'noauth')
            
            if auth_type == 'noauth':
                analysis['authentication_summary']['no_auth'] += 1
            elif auth_type == 'basic':
                analysis['authentication_summary']['basic_auth'] += 1
            elif auth_type == 'bearer':
                analysis['authentication_summary']['bearer_token'] += 1
            elif auth_type in ['apikey', 'api-key']:
                analysis['authentication_summary']['api_key'] += 1
            elif auth_type in ['oauth1', 'oauth2']:
                analysis['authentication_summary']['oauth'] += 1
            else:
                analysis['authentication_summary']['other'] += 1
            
            auth_methods.append(auth_type)
            
            # Check for sensitive endpoints
            url = api.get('url', '').lower()
            method = api.get('method', 'GET').upper()
            
            if any(pattern in url for pattern in ['/admin', '/delete', '/user', '/account', '/config']):
                sensitive_endpoints.append({
                    'name': api.get('name', 'Unknown'),
                    'url': url,
                    'method': method,
                    'auth_type': auth_type
                })
        
        # Generate security issues
        if analysis['authentication_summary']['no_auth'] > 0:
            analysis['security_issues'].append(
                f"{analysis['authentication_summary']['no_auth']} APIs have no authentication configured"
            )
        
        if analysis['authentication_summary']['basic_auth'] > 0:
            analysis['security_issues'].append(
                f"{analysis['authentication_summary']['basic_auth']} APIs use basic authentication (consider upgrading)"
            )
        
        # Check for mixed authentication
        unique_auth_methods = set(auth_methods)
        if len(unique_auth_methods) > 2:
            analysis['security_issues'].append(
                f"Inconsistent authentication methods across collection: {', '.join(unique_auth_methods)}"
            )
        
        # Check sensitive endpoints without proper auth
        for endpoint in sensitive_endpoints:
            if endpoint['auth_type'] == 'noauth':
                analysis['security_issues'].append(
                    f"Sensitive endpoint '{endpoint['name']}' has no authentication"
                )
        
        # Generate recommendations
        if analysis['authentication_summary']['no_auth'] > 0:
            analysis['recommendations'].append("Implement authentication for all API endpoints")
        
        if analysis['authentication_summary']['basic_auth'] > 0:
            analysis['recommendations'].append("Consider upgrading from basic auth to token-based authentication")
        
        if len(unique_auth_methods) > 2:
            analysis['recommendations'].append("Standardize authentication methods across the API collection")
        
        analysis['recommendations'].extend([
            "Implement proper error handling that doesn't leak sensitive information",
            "Add rate limiting to prevent abuse",
            "Use HTTPS for all API communications",
            "Implement proper input validation and sanitization"
        ])
        
        return analysis