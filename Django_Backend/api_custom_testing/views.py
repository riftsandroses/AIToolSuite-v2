from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import transaction
from .serializers import ScanRequestSerializer, ScanResultSerializer
from .services import LLMService, ChatGPTService, SQLMapService, DatabaseService
from .models import ScanResult
import logging
import traceback

logger = logging.getLogger(__name__)

class SQLInjectionTestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def __init__(self):
        super().__init__()
        self.llm_service = None
        self.sqlmap_service = None
        self.db_service = DatabaseService()
    
    def post(self, request):
        """
        Test APIs for SQL injection vulnerabilities using local LLM
        """
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid request data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Initialize services
            if not self.llm_service:
                try:
                    self.llm_service = LLMService()
                except Exception as e:
                    logger.error(f"Failed to initialize LLM service: {str(e)}")
                    return Response(
                        {"error": "LLM service unavailable", "details": str(e)},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
            
            if not self.sqlmap_service:
                try:
                    self.sqlmap_service = SQLMapService()
                except Exception as e:
                    logger.error(f"Failed to initialize SQLMap service: {str(e)}")
                    return Response(
                        {"error": "SQLMap service unavailable", "details": str(e)},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
            
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
            logger.info(f"Retrieved token for scan {scan_id}: {'Yes' if token else 'No'}")
            
            # Send to LLM in smaller batches for analysis
            BATCH_SIZE = 5  # Reduced batch size
            vulnerable_api_ids = []
            
            try:
                for i in range(0, len(apis), BATCH_SIZE):
                    api_batch = apis[i:i + BATCH_SIZE]
                    batch_num = i // BATCH_SIZE + 1
                    total_batches = (len(apis) - 1) // BATCH_SIZE + 1
                    
                    logger.info(f"Analyzing API batch {batch_num} of {total_batches} ({len(api_batch)} APIs)")
                    
                    try:
                        batch_ids = self.llm_service.analyze_apis_for_sql_injection(api_batch)
                        vulnerable_api_ids.extend(batch_ids)
                        logger.info(f"Batch {batch_num} identified {len(batch_ids)} vulnerable APIs")
                    except Exception as e:
                        logger.error(f"Error analyzing batch {batch_num}: {str(e)}")
                        continue
                
                logger.info(f"LLM identified {len(vulnerable_api_ids)} potentially vulnerable APIs total")
                
            except Exception as e:
                logger.error(f"Error during LLM analysis: {str(e)}")
                # Continue with all APIs if LLM fails
                vulnerable_api_ids = [str(api['id']) for api in apis]
                logger.info("LLM analysis failed, testing all APIs with SQLMap")
            
            # Filter APIs that LLM identified as potentially vulnerable
            if vulnerable_api_ids:
                vulnerable_apis = [api for api in apis if str(api['id']) in vulnerable_api_ids]
            else:
                # If no APIs identified by LLM, test a sample
                vulnerable_apis = apis[:3]  # Test first 3 APIs as sample
                logger.info("No APIs identified by LLM, testing first 3 APIs as sample")
            
            # Test each potentially vulnerable API with sqlmap
            results = []
            successful_tests = 0
            failed_tests = 0
            
            for i, api in enumerate(vulnerable_apis):
                logger.info(f"Testing API {api['id']} ({i+1}/{len(vulnerable_apis)}) with SQLMap")
                
                try:
                    sqlmap_result = self.sqlmap_service.test_sql_injection(api, token)
                    
                    # Save result to database
                    with transaction.atomic():
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
                            'method': api.get('method', 'GET'),
                            'vulnerable': sqlmap_result.get('vulnerable', False),
                            'severity': sqlmap_result.get('severity', 'info'),
                            'details': sqlmap_result.get('details', ''),
                            'scan_result_id': scan_result.id
                        }
                        results.append(result_data)
                    
                    successful_tests += 1
                    if sqlmap_result.get('vulnerable'):
                        logger.warning(f"VULNERABILITY FOUND in API {api['id']}: {api['url']}")
                    
                except Exception as e:
                    logger.error(f"Error testing API {api['id']}: {str(e)}")
                    failed_tests += 1
                    
                    # Still save a failed result
                    try:
                        with transaction.atomic():
                            scan_result = ScanResult.objects.create(
                                scan_id=scan_id,
                                api_id=str(api['id']),
                                vulnerability_type='SQL_INJECTION',
                                severity='error',
                                details=f'Testing failed: {str(e)}'
                            )
                            
                            result_data = {
                                'api_id': api['id'],
                                'url': api['url'],
                                'method': api.get('method', 'GET'),
                                'vulnerable': False,
                                'severity': 'error',
                                'details': f'Testing failed: {str(e)}',
                                'scan_result_id': scan_result.id
                            }
                            results.append(result_data)
                    except Exception as save_error:
                        logger.error(f"Failed to save error result: {str(save_error)}")
            
            # Prepare response
            confirmed_vulnerable = len([r for r in results if r['vulnerable']])
            
            response_data = {
                'scan_id': scan_id,
                'analysis_method': 'local_llm',
                'total_apis_found': len(apis),
                'llm_identified_vulnerable': len(vulnerable_api_ids),
                'sqlmap_tested': len(vulnerable_apis),
                'successful_tests': successful_tests,
                'failed_tests': failed_tests,
                'confirmed_vulnerable': confirmed_vulnerable,
                'results': results
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ChatGPTSQLInjectionTestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def __init__(self):
        super().__init__()
        self.chatgpt_service = None
        self.sqlmap_service = None
        self.db_service = DatabaseService()
    
    def post(self, request):
        """
        Test APIs for SQL injection vulnerabilities using ChatGPT
        """
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid request data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        scan_id = serializer.validated_data['scan_id']
        
        try:
            # Initialize services
            if not self.chatgpt_service:
                try:
                    self.chatgpt_service = ChatGPTService()
                except ValueError as e:
                    logger.error(f"ChatGPT service initialization failed: {str(e)}")
                    return Response(
                        {"error": "ChatGPT service not available. Please configure OPENAI_API_KEY in settings."},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
                except Exception as e:
                    logger.error(f"Unexpected error initializing ChatGPT service: {str(e)}")
                    return Response(
                        {"error": "ChatGPT service unavailable", "details": str(e)},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
            
            if not self.sqlmap_service:
                try:
                    self.sqlmap_service = SQLMapService()
                except Exception as e:
                    logger.error(f"Failed to initialize SQLMap service: {str(e)}")
                    return Response(
                        {"error": "SQLMap service unavailable", "details": str(e)},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
            
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
            
            logger.info(f"Found {len(apis)} APIs for scan {scan_id} (ChatGPT analysis)")
            
            # Get JWT token
            token = self.db_service.get_scan_token(scan_id)
            logger.info(f"Retrieved token for scan {scan_id}: {'Yes' if token else 'No'}")
            
            # Send to ChatGPT in smaller batches for analysis
            BATCH_SIZE = 5  # Reduced batch size
            vulnerable_api_ids = []
            
            try:
                for i in range(0, len(apis), BATCH_SIZE):
                    api_batch = apis[i:i + BATCH_SIZE]
                    batch_num = i // BATCH_SIZE + 1
                    total_batches = (len(apis) - 1) // BATCH_SIZE + 1
                    
                    logger.info(f"Analyzing API batch {batch_num} of {total_batches} ({len(api_batch)} APIs) with ChatGPT")
                    
                    try:
                        batch_ids = self.chatgpt_service.analyze_apis_for_sql_injection(api_batch)
                        vulnerable_api_ids.extend(batch_ids)
                        logger.info(f"Batch {batch_num} identified {len(batch_ids)} vulnerable APIs")
                    except Exception as e:
                        logger.error(f"Error analyzing batch {batch_num} with ChatGPT: {str(e)}")
                        continue
                
                logger.info(f"ChatGPT identified {len(vulnerable_api_ids)} potentially vulnerable APIs total")
                
            except Exception as e:
                logger.error(f"Error during ChatGPT analysis: {str(e)}")
                # Continue with all APIs if ChatGPT fails
                vulnerable_api_ids = [str(api['id']) for api in apis]
                logger.info("ChatGPT analysis failed, testing all APIs with SQLMap")
            
            # Filter APIs that ChatGPT identified as potentially vulnerable
            if vulnerable_api_ids:
                vulnerable_apis = [api for api in apis if str(api['id']) in vulnerable_api_ids]
            else:
                # If no APIs identified by ChatGPT, test a sample
                vulnerable_apis = apis[:3]  # Test first 3 APIs as sample
                logger.info("No APIs identified by ChatGPT, testing first 3 APIs as sample")
            
            # Test each potentially vulnerable API with sqlmap
            results = []
            successful_tests = 0
            failed_tests = 0
            
            for i, api in enumerate(vulnerable_apis):
                logger.info(f"Testing API {api['id']} ({i+1}/{len(vulnerable_apis)}) with SQLMap (ChatGPT identified)")
                
                try:
                    sqlmap_result = self.sqlmap_service.test_sql_injection(api, token)
                    
                    # Save result to database
                    with transaction.atomic():
                        scan_result = ScanResult.objects.create(
                            scan_id=scan_id,
                            api_id=str(api['id']),
                            vulnerability_type='SQL_INJECTION_CHATGPT',
                            severity=sqlmap_result.get('severity', 'info'),
                            details=sqlmap_result.get('details', '')
                        )
                        
                        result_data = {
                            'api_id': api['id'],
                            'url': api['url'],
                            'method': api.get('method', 'GET'),
                            'vulnerable': sqlmap_result.get('vulnerable', False),
                            'severity': sqlmap_result.get('severity', 'info'),
                            'details': sqlmap_result.get('details', ''),
                            'scan_result_id': scan_result.id
                        }
                        results.append(result_data)
                    
                    successful_tests += 1
                    if sqlmap_result.get('vulnerable'):
                        logger.warning(f"VULNERABILITY FOUND in API {api['id']}: {api['url']}")
                    
                except Exception as e:
                    logger.error(f"Error testing API {api['id']}: {str(e)}")
                    failed_tests += 1
                    
                    # Still save a failed result
                    try:
                        with transaction.atomic():
                            scan_result = ScanResult.objects.create(
                                scan_id=scan_id,
                                api_id=str(api['id']),
                                vulnerability_type='SQL_INJECTION_CHATGPT',
                                severity='error',
                                details=f'Testing failed: {str(e)}'
                            )
                            
                            result_data = {
                                'api_id': api['id'],
                                'url': api['url'],
                                'method': api.get('method', 'GET'),
                                'vulnerable': False,
                                'severity': 'error',
                                'details': f'Testing failed: {str(e)}',
                                'scan_result_id': scan_result.id
                            }
                            results.append(result_data)
                    except Exception as save_error:
                        logger.error(f"Failed to save error result: {str(save_error)}")
            
            # Prepare response
            confirmed_vulnerable = len([r for r in results if r['vulnerable']])
            
            response_data = {
                'scan_id': scan_id,
                'analysis_method': 'chatgpt',
                'total_apis_found': len(apis),
                'chatgpt_identified_vulnerable': len(vulnerable_api_ids),
                'sqlmap_tested': len(vulnerable_apis),
                'successful_tests': successful_tests,
                'failed_tests': failed_tests,
                'confirmed_vulnerable': confirmed_vulnerable,
                'results': results
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error processing scan {scan_id} with ChatGPT: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                {"error": "Internal server error", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanResultsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, scan_id=None):
        """Get scan results"""
        if not scan_id:
            return Response(
                {"error": "scan_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            results = ScanResult.objects.filter(scan_id=scan_id).order_by('-created_at')
            serializer = ScanResultSerializer(results, many=True)
            
            # Add some statistics
            total_results = results.count()
            vulnerable_count = results.filter(
                vulnerability_type__in=['SQL_INJECTION', 'SQL_INJECTION_CHATGPT'],
                details__icontains='vulnerable'
            ).count()
            
            return Response({
                'scan_id': scan_id,
                'total_results': total_results,
                'vulnerable_count': vulnerable_count,
                'results': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error retrieving scan results for {scan_id}: {str(e)}")
            return Response(
                {"error": "Error retrieving results", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )