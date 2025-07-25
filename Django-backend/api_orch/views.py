# api_orch/views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
import re
import json
import requests
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from .utils.test_case_utils import TestCaseDefinitions
from django.shortcuts import get_object_or_404
from .tasks import perform_full_login
from .models import Scan, PostmanAPI, TestCaseSelection, ScanTokens
from .serializers import (
    ScanSerializer, 
    ScanListSerializer, 
    ScanUpdateSerializer, 
    PostmanAPISerializer,
    ScanTestCaseSelectionSerializer,
    ScanTestCaseUpdateSerializer,
    TestCaseSelectionSerializer
)
logger = logging.getLogger(__name__)

class ScanCreateView(generics.CreateAPIView):
    """Create a new scan with Postman collection file"""
    serializer_class = ScanSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def perform_create(self, serializer):
        print(f"Files received: {self.request.FILES}")
        print(f"Data received: {self.request.data}")
        serializer.save(created_by=self.request.user)


class ScanListView(generics.ListAPIView):
    """List all scans created by the logged-in user"""
    serializer_class = ScanListSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.filter(created_by=self.request.user)


class ScanDetailView(generics.RetrieveAPIView):
    """Get detailed information about a specific scan"""
    serializer_class = ScanSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.filter(created_by=self.request.user)


class ScanUpdateView(generics.UpdateAPIView):
    """Update a scan (supports partial updates)"""
    serializer_class = ScanUpdateSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def get_queryset(self):
        return Scan.objects.filter(created_by=self.request.user)


class ScanDeleteView(generics.DestroyAPIView):
    """Delete a scan"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.filter(created_by=self.request.user)


class PostmanAPIListView(generics.ListAPIView):
    """List all PostmanAPI objects for a specific scan"""
    serializer_class = PostmanAPISerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        # Ensure the scan belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=self.request.user)
        return PostmanAPI.objects.filter(scan=scan)


class PostmanAPIDetailView(generics.RetrieveAPIView):
    """Get detailed information about a specific PostmanAPI"""
    serializer_class = PostmanAPISerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        # Ensure the scan belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=self.request.user)
        return PostmanAPI.objects.filter(scan=scan)


class PostmanAPIUpdateView(generics.UpdateAPIView):
    """Update a PostmanAPI (supports partial updates)"""
    serializer_class = PostmanAPISerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        # Ensure the scan belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=self.request.user)
        return PostmanAPI.objects.filter(scan=scan)


class PostmanAPIDeleteView(generics.DestroyAPIView):
    """Delete a PostmanAPI"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        scan_id = self.kwargs.get('scan_id')
        # Ensure the scan belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=self.request.user)
        return PostmanAPI.objects.filter(scan=scan)


class PostmanAPICreateView(generics.CreateAPIView):
    """Create a new PostmanAPI for a specific scan"""
    serializer_class = PostmanAPISerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        scan_id = self.kwargs.get('scan_id')
        # Ensure the scan belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=self.request.user)
        serializer.save(scan=scan)


class ScanTestCaseSelectionView(APIView):
    """
    API endpoint to update test case selections for a scan
    
    POST /api/scans/{scan_id}/test-cases/
    
    Expected payload:
    {
        "selected_categories": ["API1:2023", "API9:2023"],
        "category_test_cases": {
            "API1:2023": ["TC-1: Unlisted Endpoints", "TC-2: Access Staging/Dev Environments"],
            "API9:2023": ["TC-1: Unlisted Endpoints", "TC-7: Admin APIs"]
        }
    }
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id):
        # Get the scan and ensure it belongs to the current user
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        # Validate the input data
        serializer = ScanTestCaseSelectionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        validated_data = serializer.validated_data
        selected_categories = validated_data.get('selected_categories', [])
        category_test_cases = validated_data.get('category_test_cases', {})
        
        # Prepare the test case selections data to save
        test_case_selections = {}
        
        # If only categories are selected without specific test cases
        if selected_categories and not category_test_cases:
            for category in selected_categories:
                test_case_selections[category] = []
        
        # If specific test cases are selected for categories
        if category_test_cases:
            test_case_selections.update(category_test_cases)
        
        # Update the scan with test case selections
        scan.test_case_selections = test_case_selections
        scan.save()
        
        return Response({
            "message": "Test case selections updated successfully",
            "scan_id": scan.id,
            "scan_name": scan.scan_name,
            "test_case_selections": scan.test_case_selections
        }, status=status.HTTP_200_OK)
    
    def get(self, request, scan_id):
        """Get current test case selections for a scan"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        return Response({
            "scan_id": scan.id,
            "scan_name": scan.scan_name,
            "test_case_selections": scan.test_case_selections
        }, status=status.HTTP_200_OK)

class AvailableTestCasesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        available_categories = TestCaseDefinitions.get_valid_categories()
        test_case_definitions = TestCaseDefinitions.get_test_case_definitions()
        category_descriptions = TestCaseDefinitions.get_category_descriptions()

        categories_with_test_cases = {}

        for category in available_categories:
            cases = test_case_definitions.get(category, {})
            formatted_cases = [
                {"code": code, "name": name}
                for code, name in cases.items()
            ]
            categories_with_test_cases[category] = {
                "description": category_descriptions.get(category, ""),
                "test_cases": formatted_cases
            }

        return Response({
            "categories": available_categories,
            "details": categories_with_test_cases,
            "summary": {
                "total_categories": len(available_categories),
                "test_cases_per_category": 7
            }
        })

class BulkTestCaseSelectionView(APIView):
    """
    API endpoint to update test case selections for multiple scans
    
    POST /api/scans/bulk-test-cases/
    
    Expected payload:
    {
        "scan_selections": {
            "1": {
                "selected_categories": ["API1:2023"],
                "category_test_cases": {"API1:2023": ["TC-1: Unlisted Endpoints"]}
            },
            "2": {
                "selected_categories": ["API9:2023"],
                "category_test_cases": {"API9:2023": ["TC-7: Admin APIs"]}
            }
        }
    }
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        scan_selections = request.data.get('scan_selections', {})
        
        if not scan_selections:
            return Response(
                {"error": "scan_selections is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        results = {}
        errors = {}
        
        for scan_id, selection_data in scan_selections.items():
            try:
                # Get the scan and ensure it belongs to the current user
                scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
                
                # Validate the selection data
                serializer = ScanTestCaseSelectionSerializer(data=selection_data)
                if not serializer.is_valid():
                    errors[scan_id] = serializer.errors
                    continue
                
                validated_data = serializer.validated_data
                selected_categories = validated_data.get('selected_categories', [])
                category_test_cases = validated_data.get('category_test_cases', {})
                
                # Prepare the test case selections data
                test_case_selections = {}
                
                if selected_categories and not category_test_cases:
                    for category in selected_categories:
                        test_case_selections[category] = []
                
                if category_test_cases:
                    test_case_selections.update(category_test_cases)
                
                # Update the scan
                scan.test_case_selections = test_case_selections
                scan.save()
                
                results[scan_id] = {
                    "scan_name": scan.scan_name,
                    "test_case_selections": scan.test_case_selections,
                    "status": "success"
                }
                
            except Exception as e:
                errors[scan_id] = str(e)
        
        response_data = {
            "results": results,
            "errors": errors,
            "total_processed": len(scan_selections),
            "successful": len(results),
            "failed": len(errors)
        }
        
        if errors:
            return Response(response_data, status=status.HTTP_207_MULTI_STATUS)
        
        return Response(response_data, status=status.HTTP_200_OK)
    
class ScanEnvironmentView(APIView):
    """
    API endpoint to manage environment variables for a scan
    
    GET /api/scans/{scan_id}/environment/
    POST /api/scans/{scan_id}/environment/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get environment variables for a scan"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        return Response({
            "scan_id": scan.id,
            "scan_name": scan.scan_name,
            "environment_variables": scan.environment_variables,
            "environment_file": scan.postman_environment_file.url if scan.postman_environment_file else None
        }, status=status.HTTP_200_OK)
    
    def post(self, request, scan_id):
        """Update environment variables manually or upload new environment file"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        # Check if environment file is being uploaded
        if 'postman_environment_file' in request.FILES:
            scan.postman_environment_file = request.FILES['postman_environment_file']
            scan.save()
            
            # Parse the new environment file
            try:
                self._parse_environment_file(scan)
                self._update_apis_with_environment(scan)
                
                return Response({
                    "message": "Environment file uploaded and processed successfully",
                    "scan_id": scan.id,
                    "environment_variables": scan.environment_variables
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                return Response({
                    "error": f"Error parsing environment file: {str(e)}"
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if environment variables are being updated manually
        elif 'environment_variables' in request.data:
            environment_variables = request.data['environment_variables']
            
            if not isinstance(environment_variables, dict):
                return Response({
                    "error": "environment_variables must be a dictionary"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            scan.environment_variables = environment_variables
            scan.save()
            
            # Update existing APIs with new environment variables
            self._update_apis_with_environment(scan)
            
            return Response({
                "message": "Environment variables updated successfully",
                "scan_id": scan.id,
                "environment_variables": scan.environment_variables
            }, status=status.HTTP_200_OK)
        
        else:
            return Response({
                "error": "Either 'postman_environment_file' or 'environment_variables' must be provided"
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def _parse_environment_file(self, scan):
        """Parse Postman environment file and extract variables"""
        try:
            with scan.postman_environment_file.open('r') as file:
                environment_data = json.load(file)
            
            environment_variables = {}
            
            # Extract values from environment file
            values = environment_data.get('values', [])
            for item in values:
                if item.get('enabled', True):  # Only include enabled variables
                    key = item.get('key', '')
                    value = item.get('value', '')
                    if key:  # Only add if key is not empty
                        environment_variables[key] = value
            
            # Save environment variables to scan
            scan.environment_variables = environment_variables
            scan.save()
            
            print(f"Parsed {len(environment_variables)} environment variables")
            
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON in Postman environment file: {str(e)}")
        except Exception as e:
            raise Exception(f"Error reading Postman environment file: {str(e)}")
    
    def _replace_environment_variables(self, text, environment_variables):
        """Replace {{variable}} placeholders with environment variable values"""
        if not isinstance(text, str) or not environment_variables:
            return text
        
        # Pattern to match {{variable_name}}
        pattern = r'\{\{([^}]+)\}\}'
        
        def replace_match(match):
            var_name = match.group(1).strip()
            return environment_variables.get(var_name, match.group(0))  # Return original if not found
        
        return re.sub(pattern, replace_match, text)
    
    def _replace_variables_in_dict(self, data, environment_variables):
        """Recursively replace environment variables in dictionary/list structures"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                new_key = self._replace_environment_variables(key, environment_variables)
                result[new_key] = self._replace_variables_in_dict(value, environment_variables)
            return result
        elif isinstance(data, list):
            return [self._replace_variables_in_dict(item, environment_variables) for item in data]
        elif isinstance(data, str):
            return self._replace_environment_variables(data, environment_variables)
        else:
            return data
    
    def _update_apis_with_environment(self, scan):
        """Update existing APIs with environment variables"""
        environment_variables = scan.environment_variables
        
        for api in scan.postman_apis.all():
            # Use original values and apply environment variables
            if environment_variables:
                api.url = self._replace_environment_variables(api.original_url, environment_variables)
                api.headers = self._replace_variables_in_dict(api.original_headers, environment_variables)
                api.body = self._replace_variables_in_dict(api.original_body, environment_variables)
                api.query_params = self._replace_variables_in_dict(api.original_query_params, environment_variables)
            else:
                # If no environment variables, revert to original values
                api.url = api.original_url
                api.headers = api.original_headers
                api.body = api.original_body
                api.query_params = api.original_query_params
            
            api.save()


class ScanEnvironmentVariablesView(APIView):
    """
    API endpoint to get/set specific environment variables
    
    GET /api/scans/{scan_id}/environment/variables/
    PUT /api/scans/{scan_id}/environment/variables/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get specific environment variables with their usage count"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        # Count usage of each variable in APIs
        variable_usage = {}
        environment_variables = scan.environment_variables or {}
        
        for var_name in environment_variables.keys():
            usage_count = 0
            pattern = f"{{{{{var_name}}}}}"
            
            for api in scan.postman_apis.all():
                # Check in original values for accurate count
                if pattern in str(api.original_url):
                    usage_count += 1
                if pattern in str(api.original_headers):
                    usage_count += 1
                if pattern in str(api.original_body):
                    usage_count += 1
                if pattern in str(api.original_query_params):
                    usage_count += 1
            
            variable_usage[var_name] = usage_count
        
        return Response({
            "scan_id": scan.id,
            "scan_name": scan.scan_name,
            "environment_variables": environment_variables,
            "variable_usage": variable_usage,
            "total_variables": len(environment_variables),
            "total_apis": scan.postman_apis.count()
        }, status=status.HTTP_200_OK)
    
    def put(self, request, scan_id):
        """Update specific environment variables"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        updates = request.data.get('updates', {})
        if not isinstance(updates, dict):
            return Response({
                "error": "updates must be a dictionary"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Update the environment variables
        current_env = scan.environment_variables or {}
        current_env.update(updates)
        scan.environment_variables = current_env
        scan.save()
        
        # Update APIs with new variables
        self._update_apis_with_environment(scan)
        
        return Response({
            "message": f"Updated {len(updates)} environment variables",
            "scan_id": scan.id,
            "updated_variables": list(updates.keys()),
            "environment_variables": scan.environment_variables
        }, status=status.HTTP_200_OK)
    
    def _replace_environment_variables(self, text, environment_variables):
        """Replace {{variable}} placeholders with environment variable values"""
        if not isinstance(text, str) or not environment_variables:
            return text
        
        pattern = r'\{\{([^}]+)\}\}'
        
        def replace_match(match):
            var_name = match.group(1).strip()
            return environment_variables.get(var_name, match.group(0))
        
        return re.sub(pattern, replace_match, text)
    
    def _replace_variables_in_dict(self, data, environment_variables):
        """Recursively replace environment variables in dictionary/list structures"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                new_key = self._replace_environment_variables(key, environment_variables)
                result[new_key] = self._replace_variables_in_dict(value, environment_variables)
            return result
        elif isinstance(data, list):
            return [self._replace_variables_in_dict(item, environment_variables) for item in data]
        elif isinstance(data, str):
            return self._replace_environment_variables(data, environment_variables)
        else:
            return data
    
    def _update_apis_with_environment(self, scan):
        """Update existing APIs with environment variables"""
        environment_variables = scan.environment_variables
        
        for api in scan.postman_apis.all():
            if environment_variables:
                api.url = self._replace_environment_variables(api.original_url, environment_variables)
                api.headers = self._replace_variables_in_dict(api.original_headers, environment_variables)
                api.body = self._replace_variables_in_dict(api.original_body, environment_variables)
                api.query_params = self._replace_variables_in_dict(api.original_query_params, environment_variables)
            else:
                api.url = api.original_url
                api.headers = api.original_headers
                api.body = api.original_body
                api.query_params = api.original_query_params
            
            api.save()

class ScanTokenManagementView(APIView):
    """
    API endpoint to manage authentication tokens for scans
    
    POST /api/scans/{scan_id}/tokens/login/
    GET /api/scans/{scan_id}/tokens/status/
    POST /api/scans/{scan_id}/tokens/refresh/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id):
        """Perform login and obtain tokens"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        try:
            # Find login/signin API
            login_api = self._find_login_api(scan)
            if not login_api:
                return Response({
                    "error": "No login/signin API found for this scan",
                    "details": "Please ensure your Postman collection contains an API with 'login' or 'signin' in its name"
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Perform login request
            token_data = self._perform_login_request(scan, login_api)
            
            # Save tokens to database
            self._save_tokens(scan, token_data, login_api)
            
            return Response({
                "message": "Login successful, tokens obtained",
                "scan_id": scan.id,
                "scan_name": scan.scan_name,
                "login_api": login_api.name,
                "token_expires_at": token_data.get('expires_at'),
                "has_access_token": bool(token_data.get('access_token')),
                "has_refresh_token": bool(token_data.get('refresh_token'))
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            # Log the error and save it to the database
            self._save_login_error(scan, str(e))
            
            return Response({
                "error": "Login failed",
                "details": str(e),
                "scan_id": scan.id
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, scan_id):
        """Get token status for a scan"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        try:
            scan_tokens = scan.tokens
            
            return Response({
                "scan_id": scan.id,
                "scan_name": scan.scan_name,
                "has_tokens": bool(scan_tokens.access_token),
                "token_expires_at": scan_tokens.token_expires_at,
                "is_expired": scan_tokens.is_token_expired(),
                "last_login_attempt": scan_tokens.last_login_attempt,
                "login_successful": scan_tokens.login_successful,
                "login_error_message": scan_tokens.login_error_message,
                "created_at": scan_tokens.created_at,
                "updated_at": scan_tokens.updated_at
            }, status=status.HTTP_200_OK)
            
        except ScanTokens.DoesNotExist:
            return Response({
                "scan_id": scan.id,
                "scan_name": scan.scan_name,
                "has_tokens": False,
                "message": "No tokens found. Please perform login first."
            }, status=status.HTTP_404_NOT_FOUND)
    
    def _find_login_api(self, scan):
        """Find the login/signin API in the scan's PostmanAPI objects"""
        login_keywords = ['login', 'signin', 'sign-in', 'auth', 'authenticate', 'token']
        
        # First, try to find exact matches
        for keyword in login_keywords:
            login_apis = scan.postman_apis.filter(
                name__icontains=keyword,
                method='POST'
            )
            if login_apis.exists():
                return login_apis.first()
        
        # If no exact match, look for APIs that might be login endpoints
        potential_login_apis = scan.postman_apis.filter(method='POST')
        
        for api in potential_login_apis:
            # Check if URL contains login-related keywords
            url_lower = api.url.lower() if api.url else ''
            if any(keyword in url_lower for keyword in login_keywords):
                return api
            
            # Check if body contains username/password fields
            if api.body and isinstance(api.body, dict):
                body_str = json.dumps(api.body).lower()
                if ('username' in body_str or 'email' in body_str) and 'password' in body_str:
                    return api
        
        return None
    
    def _perform_login_request(self, scan, login_api):
        """Perform the actual login request"""
        if not login_api.url:
            raise Exception("Login API URL is empty")
        
        # Prepare headers
        headers = login_api.headers.copy() if login_api.headers else {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        # Prepare body with username and password
        body = self._prepare_login_body(scan, login_api)
        
        # Make the request
        try:
            response = requests.post(
                url=login_api.url,
                headers=headers,
                json=body,
                timeout=30
            )
            
            if response.status_code not in [200, 201]:
                raise Exception(f"Login request failed with status {response.status_code}: {response.text}")
            
            response_data = response.json()
            
            # Extract tokens from response
            token_data = self._extract_tokens_from_response(response_data)
            
            return token_data
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
        except json.JSONDecodeError:
            raise Exception("Invalid JSON response from login API")
    
    def _prepare_login_body(self, scan, login_api):
        """Prepare the request body with username and password"""
        body = login_api.body.copy() if login_api.body else {}
        
        # Handle different body formats
        if isinstance(body, dict):
            if body.get('mode') == 'raw':
                # Try to parse raw body as JSON
                try:
                    raw_body = json.loads(body.get('raw', '{}'))
                    # Update with username and password
                    raw_body = self._inject_credentials(raw_body, scan)
                    return raw_body
                except json.JSONDecodeError:
                    # If not JSON, create new body
                    return self._create_default_login_body(scan)
            
            elif body.get('mode') == 'urlencoded':
                # Handle form data
                form_data = {}
                for item in body.get('urlencoded', []):
                    if not item.get('disabled', False):
                        form_data[item.get('key', '')] = item.get('value', '')
                
                # Inject credentials
                form_data = self._inject_credentials(form_data, scan)
                return form_data
            
            else:
                # Direct dictionary body
                return self._inject_credentials(body, scan)
        
        else:
            # Create default login body
            return self._create_default_login_body(scan)
    
    def _inject_credentials(self, body_dict, scan):
        """Inject username and password into the body dictionary"""
        # Common field names for username
        username_fields = ['username', 'email', 'user', 'login', 'account']
        password_fields = ['password', 'pass', 'pwd']
        
        # Look for existing fields and update them
        username_set = False
        password_set = False
        
        for key in body_dict.keys():
            key_lower = key.lower()
            
            if not username_set and any(field in key_lower for field in username_fields):
                body_dict[key] = scan.username
                username_set = True
            
            if not password_set and any(field in key_lower for field in password_fields):
                body_dict[key] = scan.password
                password_set = True
        
        # If fields not found, add them
        if not username_set:
            body_dict['username'] = scan.username
        
        if not password_set:
            body_dict['password'] = scan.password
        
        return body_dict
    
    def _create_default_login_body(self, scan):
        """Create a default login body with username and password"""
        return {
            'username': scan.username,
            'password': scan.password
        }
    
    def _extract_tokens_from_response(self, response_data):
        """Extract access and refresh tokens from the response"""
        token_data = {}
        
        # Common field names for tokens
        access_token_fields = ['access_token', 'accessToken', 'token', 'authToken', 'jwt', 'access']
        refresh_token_fields = ['refresh_token', 'refreshToken', 'refresh']
        
        # Look for tokens in the response
        def find_token_in_dict(data, field_names):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = key.lower()
                    if any(field in key_lower for field in field_names):
                        return value
                    
                    # Recursively search nested objects
                    if isinstance(value, dict):
                        found = find_token_in_dict(value, field_names)
                        if found:
                            return found
            return None
        
        # Extract access token
        access_token = find_token_in_dict(response_data, access_token_fields)
        if access_token:
            token_data['access_token'] = access_token
        
        # Extract refresh token
        refresh_token = find_token_in_dict(response_data, refresh_token_fields)
        if refresh_token:
            token_data['refresh_token'] = refresh_token
        
        # Calculate expiration time (default to 15 minutes if not specified)
        expires_in = response_data.get('expires_in', 900)  # Default 15 minutes
        if isinstance(expires_in, (int, float)):
            token_data['expires_at'] = timezone.now() + timedelta(seconds=expires_in)
        else:
            token_data['expires_at'] = timezone.now() + timedelta(minutes=15)
        
        if not access_token:
            raise Exception("No access token found in login response")
        
        return token_data
    
    def _save_tokens(self, scan, token_data, login_api):
        """Save tokens to the database"""
        with transaction.atomic():
            scan_tokens, created = ScanTokens.objects.get_or_create(scan=scan)
            
            scan_tokens.access_token = token_data.get('access_token')
            scan_tokens.refresh_token = token_data.get('refresh_token')
            scan_tokens.token_expires_at = token_data.get('expires_at')
            scan_tokens.last_login_attempt = timezone.now()
            scan_tokens.login_successful = True
            scan_tokens.login_error_message = None
            
            scan_tokens.save()
    
    def _save_login_error(self, scan, error_message):
        """Save login error to the database"""
        try:
            with transaction.atomic():
                scan_tokens, created = ScanTokens.objects.get_or_create(scan=scan)
                
                scan_tokens.last_login_attempt = timezone.now()
                scan_tokens.login_successful = False
                scan_tokens.login_error_message = error_message
                
                scan_tokens.save()
        except Exception as e:
            print(f"Error saving login error: {str(e)}")


class ScanTokenRefreshView(APIView):
    """
    API endpoint to refresh tokens automatically
    
    POST /api/scans/{scan_id}/tokens/refresh/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id):
        """Refresh tokens if they are expired or about to expire"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        try:
            scan_tokens = scan.tokens
            
            # Check if token needs refresh
            if not scan_tokens.is_token_expired():
                return Response({
                    "message": "Token is still valid, no refresh needed",
                    "scan_id": scan.id,
                    "token_expires_at": scan_tokens.token_expires_at,
                    "expires_in_minutes": int((scan_tokens.token_expires_at - timezone.now()).total_seconds() / 60)
                }, status=status.HTTP_200_OK)
            
            # Try to refresh using refresh token first
            if scan_tokens.refresh_token:
                try:
                    self._refresh_using_refresh_token(scan, scan_tokens)
                    
                    return Response({
                        "message": "Tokens refreshed successfully using refresh token",
                        "scan_id": scan.id,
                        "token_expires_at": scan_tokens.token_expires_at
                    }, status=status.HTTP_200_OK)
                    
                except Exception as refresh_error:
                    print(f"Refresh token failed: {str(refresh_error)}")
                    # Fall back to full login
            
            # Perform full login if refresh token doesn't work
            login_view = ScanTokenManagementView()
            login_view.request = request
            login_result = login_view.post(request, scan_id)
            
            if login_result.status_code == 200:
                return Response({
                    "message": "Tokens refreshed successfully using full login",
                    "scan_id": scan.id,
                    "method": "full_login"
                }, status=status.HTTP_200_OK)
            else:
                return login_result
                
        except ScanTokens.DoesNotExist:
            return Response({
                "error": "No tokens found for this scan",
                "message": "Please perform login first"
            }, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({
                "error": "Token refresh failed",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def _refresh_using_refresh_token(self, scan, scan_tokens):
        """Try to refresh tokens using the refresh token"""
        # This is a placeholder - implement based on your API's refresh endpoint
        # You would need to find a refresh endpoint in your APIs or use a standard refresh flow
        
        refresh_apis = scan.postman_apis.filter(
            name__icontains='refresh',
            method='POST'
        )
        
        if not refresh_apis.exists():
            raise Exception("No refresh endpoint found")
        
        refresh_api = refresh_apis.first()
        
        if not refresh_api.url:
            raise Exception("Refresh API URL is empty")
        
        headers = refresh_api.headers.copy() if refresh_api.headers else {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        # Prepare refresh request body
        body = {
            'refresh_token': scan_tokens.refresh_token
        }
        
        response = requests.post(
            url=refresh_api.url,
            headers=headers,
            json=body,
            timeout=30
        )
        
        if response.status_code not in [200, 201]:
            raise Exception(f"Refresh request failed with status {response.status_code}")
        
        response_data = response.json()
        
        # Extract new tokens
        login_view = ScanTokenManagementView()
        token_data = login_view._extract_tokens_from_response(response_data)
        
        # Update tokens in database
        with transaction.atomic():
            scan_tokens.access_token = token_data.get('access_token')
            if token_data.get('refresh_token'):
                scan_tokens.refresh_token = token_data.get('refresh_token')
            scan_tokens.token_expires_at = token_data.get('expires_at')
            scan_tokens.last_login_attempt = timezone.now()
            scan_tokens.login_successful = True
            scan_tokens.login_error_message = None
            
            scan_tokens.save()

class ManualTokenRefreshView(APIView):
    """
    API endpoint to manually trigger token refresh for all scans or specific scan
    
    POST /api/scans/tokens/refresh-all/
    POST /api/scans/{scan_id}/tokens/refresh-manual/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id=None):
        """Manually trigger token refresh"""
        
        if scan_id:
            # Refresh specific scan
            scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
            
            try:
                # Queue the task
                task = perform_full_login.delay(scan.id)
                
                return Response({
                    "message": f"Token refresh queued for scan: {scan.scan_name}",
                    "scan_id": scan.id,
                    "task_id": task.id
                }, status=status.HTTP_202_ACCEPTED)
                
            except Exception as e:
                return Response({
                    "error": "Failed to queue token refresh",
                    "details": str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            # Refresh all user's scans
            user_scans = Scan.objects.filter(created_by=request.user)
            
            if not user_scans.exists():
                return Response({
                    "message": "No scans found for the current user"
                }, status=status.HTTP_404_NOT_FOUND)
            
            task_ids = []
            for scan in user_scans:
                try:
                    task = perform_full_login.delay(scan.id)
                    task_ids.append({
                        "scan_id": scan.id,
                        "scan_name": scan.scan_name,
                        "task_id": task.id
                    })
                except Exception as e:
                    logger.error(f"Failed to queue refresh for scan {scan.id}: {str(e)}")
            
            return Response({
                "message": f"Token refresh queued for {len(task_ids)} scans",
                "queued_tasks": task_ids,
                "total_scans": user_scans.count()
            }, status=status.HTTP_202_ACCEPTED)
        
class AuthenticatedAPIRequestView(APIView):
    """
    Helper view to make authenticated API requests using stored tokens
    
    POST /api/scans/{scan_id}/request/
    
    Body:
    {
        "api_id": 123,  # PostmanAPI ID to execute
        "override_headers": {},  # Optional header overrides
        "override_body": {}  # Optional body overrides
    }
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id):
        """Execute an API request with authentication"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        api_id = request.data.get('api_id')
        if not api_id:
            return Response({
                "error": "api_id is required"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            postman_api = scan.postman_apis.get(id=api_id)
        except PostmanAPI.DoesNotExist:
            return Response({
                "error": "API not found"
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get authenticated headers
        from .utils.token_utils import TokenManager
        
        base_headers = postman_api.headers.copy() if postman_api.headers else {}
        override_headers = request.data.get('override_headers', {})
        base_headers.update(override_headers)
        
        auth_headers, has_token = TokenManager.get_authenticated_headers(scan, base_headers)
        
        if not has_token:
            return Response({
                "error": "Unable to obtain valid authentication token",
                "suggestion": "Try refreshing tokens first"
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Prepare request body
        body = postman_api.body.copy() if postman_api.body else {}
        override_body = request.data.get('override_body', {})
        
        if override_body:
            if isinstance(body, dict) and body.get('mode') == 'raw':
                try:
                    raw_body = json.loads(body.get('raw', '{}'))
                    raw_body.update(override_body)
                    body['raw'] = json.dumps(raw_body)
                except:
                    body = override_body
            elif isinstance(body, dict):
                body.update(override_body)
            else:
                body = override_body
        
        # Make the request
        try:
            if postman_api.method.upper() == 'GET':
                response = requests.get(
                    url=postman_api.url,
                    headers=auth_headers,
                    params=postman_api.query_params,
                    timeout=30
                )
            else:
                # Handle different body formats
                request_kwargs = {
                    'url': postman_api.url,
                    'headers': auth_headers,
                    'params': postman_api.query_params,
                    'timeout': 30
                }
                
                if body:
                    if isinstance(body, dict) and body.get('mode') == 'raw':
                        request_kwargs['data'] = body.get('raw', '')
                    elif isinstance(body, dict) and body.get('mode') == 'json':
                        request_kwargs['json'] = body.get('json', {})
                    elif isinstance(body, dict):
                        request_kwargs['json'] = body
                    else:
                        request_kwargs['data'] = body
                
                response = requests.request(
                    method=postman_api.method.upper(),
                    **request_kwargs
                )
            
            # Parse response
            try:
                response_json = response.json()
            except:
                response_json = None
            
            return Response({
                "request": {
                    "method": postman_api.method,
                    "url": postman_api.url,
                    "headers": {k: v for k, v in auth_headers.items() if k != 'Authorization'},
                    "has_auth_token": has_token
                },
                "response": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "json": response_json,
                    "text": response.text if not response_json else None,
                    "success": 200 <= response.status_code < 300
                }
            }, status=status.HTTP_200_OK)
            
        except requests.exceptions.RequestException as e:
            return Response({
                "error": "Request failed",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)