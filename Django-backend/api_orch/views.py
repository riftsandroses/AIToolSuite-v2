# api_orch/views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
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
    """
    API endpoint to get all available test cases and categories
    
    GET /api/test-cases/available/
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        available_categories = [
            'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
            'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023'
        ]
        
        available_test_cases = [
            'TC-1: Unlisted Endpoints',
            'TC-2: Access Staging/Dev Environments', 
            'TC-3: API Documentation Exposure',
            'TC-4: Verb Tunneling',
            'TC-5: Version Enumeration of APIs',
            'TC-6: Monitoring/Health Endpoints',
            'TC-7: Admin APIs'
        ]
        
        return Response({
            "available_categories": available_categories,
            "available_test_cases": available_test_cases,
            "category_descriptions": {
                "API1:2023": "API Security Test Category 1",
                "API2:2023": "API Security Test Category 2",
                "API3:2023": "API Security Test Category 3",
                "API4:2023": "API Security Test Category 4",
                "API5:2023": "API Security Test Category 5",
                "API6:2023": "API Security Test Category 6",
                "API7:2023": "API Security Test Category 7",
                "API8:2023": "API Security Test Category 8",
                "API9:2023": "API Security Test Category 9"
            },
            "test_case_descriptions": {
                "TC-1": "Unlisted Endpoints - Test for undocumented API endpoints",
                "TC-2": "Access Staging/Dev Environments - Test access to non-production environments",
                "TC-3": "API Documentation Exposure - Test for exposed API documentation",
                "TC-4": "Verb Tunneling - Test for HTTP method override vulnerabilities",
                "TC-5": "Version Enumeration of APIs - Test for API version enumeration",
                "TC-6": "Monitoring/Health Endpoints - Test for exposed monitoring endpoints",
                "TC-7": "Admin APIs - Test for exposed administrative APIs"
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