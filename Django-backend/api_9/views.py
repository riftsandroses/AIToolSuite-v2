# api_9/views.py
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from django.db import connection
from .models import UnlistedEndpoints
from .serializers import EndpointDiscoverySerializer, UnlistedEndpointsSerializer
from .utils.prompts import EndpointDiscoveryService
import logging

logger = logging.getLogger(__name__)

class DiscoverEndpointsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EndpointDiscoverySerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid scan_id provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
    
        try:
            # Get URLs from api_orch_postmanapi table
            urls = self.get_urls_from_postmanapi(scan_id)
            if not urls:
                return Response(
                    {'error': f'No URLs found for scan_id: {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get JWT token from api_orch_scantokens table
            jwt_token = self.get_jwt_token(scan_id)
            if not jwt_token:
                return Response(
                    {'error': f'No JWT token found for scan_id: {scan_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Initialize discovery service
            discovery_service = EndpointDiscoveryService()
            
            all_discovered_endpoints = []
            existing_urls = set(urls)  # Convert to set for faster lookup
            
            # Process each URL
            for url in urls:
                try:
                    logger.info(f"Processing URL: {url}")
                    
                    # Get truncated URL from ChatGPT
                    truncated_url = discovery_service.get_truncated_url_from_chatgpt(url)
                    logger.info(f"Truncated URL: {truncated_url}")
                    
                    # Run feroxbuster to discover endpoints
                    discovered_endpoints = discovery_service.run_feroxbuster(truncated_url, jwt_token)
                    logger.info(f"Discovered {len(discovered_endpoints)} endpoints")
                    
                    # Filter out endpoints that already exist in the database
                    new_endpoints = []
                    for endpoint in discovered_endpoints:
                        endpoint_url = endpoint['url']
                        if endpoint_url not in existing_urls:
                            new_endpoints.append(endpoint)
                            existing_urls.add(endpoint_url)  # Add to set to avoid duplicates
                    
                    all_discovered_endpoints.extend(new_endpoints)
                    
                except Exception as e:
                    logger.error(f"Error processing URL {url}: {e}")
                    continue
            
            # Save new endpoints to database
            saved_endpoints = []
            for endpoint in all_discovered_endpoints:
                try:
                    unlisted_endpoint, created = UnlistedEndpoints.objects.get_or_create(
                        scan_id=scan_id,
                        endpoint_url=endpoint['url'],
                        defaults={
                            'method': endpoint.get('method', 'GET'),
                            'status_code': endpoint.get('status_code')
                        }
                    )
                    
                    if created:
                        saved_endpoints.append(unlisted_endpoint)
                        
                except Exception as e:
                    logger.error(f"Error saving endpoint {endpoint['url']}: {e}")
                    continue
            
            # Serialize response
            response_serializer = UnlistedEndpointsSerializer(saved_endpoints, many=True)
            
            return Response({
                'message': f'Discovery completed. Found {len(saved_endpoints)} new endpoints.',
                'scan_id': scan_id,
                'new_endpoints_count': len(saved_endpoints),
                'new_endpoints': response_serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Unexpected error in discover_endpoints: {e}")
            return Response(
                {'error': 'Internal server error occurred during endpoint discovery'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_urls_from_postmanapi(self, scan_id):
        """
        Get all URLs from api_orch_postmanapi table for given scan_id
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT DISTINCT url FROM api_orch_postmanapi WHERE scan_id = %s",
                    [scan_id]
                )
                rows = cursor.fetchall()
                return [row[0] for row in rows if row[0]]
        except Exception as e:
            logger.error(f"Error fetching URLs from postmanapi: {e}")
            return []

    def get_jwt_token(self, scan_id):
        """
        Get JWT token from api_orch_scantokens table for given scan_id
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT access_token FROM api_orch_scantokens WHERE scan_id = %s LIMIT 1",
                    [scan_id]
                )
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Error fetching JWT token: {e}")
            return None