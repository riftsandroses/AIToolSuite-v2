from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import transaction
from .serializers import ScanRequestSerializer, ScanResultSerializer
from .services import LLMService, SQLMapService, DatabaseService
from .models import ScanResult
import logging

logger = logging.getLogger(__name__)

class SQLInjectionTestView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def __init__(self):
        super().__init__()
        self.llm_service = LLMService()
        self.sqlmap_service = SQLMapService()
        self.db_service = DatabaseService()
    
    def post(self, request):
        """
        Test APIs for SQL injection vulnerabilities
        """
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid request data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Check if scan exists
            if not self.db_service.scan_exists(scan_id):
                return Response(
                    {"error": f"Scan with ID {scan_id} not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get APIs for the scan
            apis = self.db_service.get_scan_apis(scan_id)
            if not apis:
                return Response(
                    {"error": f"No APIs found for scan {scan_id}"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            logger.info(f"Found {len(apis)} APIs for scan {scan_id}")
            
            # Get JWT token
            token = self.db_service.get_scan_token(scan_id)
            logger.info(f"Retrieved token for scan {scan_id}")
            
            # Send to LLM for analysis
            vulnerable_api_ids = self.llm_service.analyze_apis_for_sql_injection(apis)
            logger.info(f"LLM identified {len(vulnerable_api_ids)} potentially vulnerable APIs")
            
            # Filter APIs that LLM identified as potentially vulnerable
            vulnerable_apis = [api for api in apis if str(api['id']) in vulnerable_api_ids]
            
            # Test each potentially vulnerable API with sqlmap
            results = []
            with transaction.atomic():
                for api in vulnerable_apis:
                    logger.info(f"Testing API {api['id']} with sqlmap")
                    sqlmap_result = self.sqlmap_service.test_sql_injection(api, token)
                    
                    # Save result to database
                    scan_result = ScanResult.objects.create(
                        scan_id=scan_id,
                        api_id=str(api['id']),
                        vulnerability_type='SQL_INJECTION',
                        severity=sqlmap_result.get('severity', 'info'),
                        details=sqlmap_result.get('details', '')
                    )
                    
                    result_data = {
                        'api_id': api['id'],
                        'url': api['url'],
                        'vulnerable': sqlmap_result.get('vulnerable', False),
                        'severity': sqlmap_result.get('severity', 'info'),
                        'details': sqlmap_result.get('details', ''),
                        'scan_result_id': scan_result.id
                    }
                    results.append(result_data)
            
            # Prepare response
            response_data = {
                'scan_id': scan_id,
                'total_apis_analyzed': len(apis),
                'llm_identified_vulnerable': len(vulnerable_api_ids),
                'sqlmap_tested': len(vulnerable_apis),
                'confirmed_vulnerable': len([r for r in results if r['vulnerable']]),
                'results': results
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {str(e)}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanResultsView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, scan_id=None):
        """Get scan results"""
        if scan_id:
            results = ScanResult.objects.filter(scan_id=scan_id)
            serializer = ScanResultSerializer(results, many=True)
            return Response({
                'scan_id': scan_id,
                'results': serializer.data
            })
        else:
            return Response(
                {"error": "scan_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )