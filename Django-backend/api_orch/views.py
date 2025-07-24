# api_orch/views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
import re
import json
from .utils.test_case_utils import TestCaseDefinitions
from django.shortcuts import get_object_or_404
from .models import Scan, PostmanAPI, TestCaseSelection
from .serializers import (
    ScanSerializer, 
    ScanListSerializer, 
    ScanUpdateSerializer, 
    PostmanAPISerializer,
    ScanTestCaseSelectionSerializer,
    ScanTestCaseUpdateSerializer,
    TestCaseSelectionSerializer
)


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