# api_orch/views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
from .models import Scan, PostmanAPI
from .serializers import (
    ScanSerializer, 
    ScanListSerializer, 
    ScanUpdateSerializer, 
    PostmanAPISerializer
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