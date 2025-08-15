import json
import requests
from openai import OpenAI
from django.conf import settings
from django.utils import timezone
from django.db import transaction, connection
from django.db.models import Count, Q
from .models import ScanResultTC1, ScanSessionTC1, VulnerabilitySummaryTC1
import logging
from typing import Dict, List, Any, Tuple
import re
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class APIOrchDataServiceTC1:
    """Service to interact with api_orch app data"""
    
    @staticmethod
    def get_apis_by_scan_id(scan_id: int) -> List[Dict]:
        """Fetch APIs from api_orch_postmanapi table by scan_id"""
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "id", "name", "method", "url", "headers", "body", "authorization", 
                       "query_params", "original_url", "original_headers", "original_body",
                       "original_query_params", "scan_id"
                FROM api_orch_postmanapi 
                WHERE "scan_id" = %s
            """, [scan_id])
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    @staticmethod
    def get_jwt_token_by_scan_id(scan_id: int) -> str:
        """Fetch JWT token from api_orch_scantokens table"""
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "access_token" 
                FROM api_orch_scantokens 
                WHERE "scan_id" = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, [scan_id])
            
            result = cursor.fetchone()
            return result[0] if result else None

class VulnerabilityAnalyzerTC1:
    """Service to analyze APIs for vulnerabilities using ChatGPT"""
    
    def __init__(self):
        if hasattr(settings, 'OPENAI_API_KEY'):
            self.client = OpenAI(api_key=settings.OPENAI_API_KEY)  # Store client as instance variable
        else:
            logger.warning("OPENAI_API_KEY not found in settings")
            self.client = None
    
    def analyze_authentication_vulnerability(self, api_data: Dict) -> Dict:
        """Analyze API for missing or weak authentication vulnerabilities"""
        try:
            if not self.client:
                return self._fallback_analysis(api_data)

            prompt = f"""
            Analyze the following API endpoint for authentication vulnerabilities:
            
            API Name: {api_data.get('name', '')}
            Method: {api_data.get('method', '')}
            URL: {api_data.get('url', '')}
            Headers: {api_data.get('headers', '{}')}
            Body: {api_data.get('body', '{}')}
            Authorization: {api_data.get('authorization', '{}')}
            
            Check for:
            1. Missing authentication headers
            2. Weak authentication methods
            3. Sensitive endpoints without proper auth
            4. Default credentials or tokens
            
            Respond ONLY with a valid JSON object in this exact format:
            {{
                "has_vulnerability": boolean,
                "severity": "critical|high|medium|low|info",
                "title": "Brief title",
                "description": "Detailed description",
                "impact": "Impact description",
                "recommendation": "Fix recommendation",
                "evidence": "Technical evidence"
            }}
            """

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.1,
                response_format={"type": "json_object"}  # Force JSON response
            )
            
            logger.debug(f"Raw API response: {response}")

            content = response.choices[0].message.content.strip()
            
            logger.debug(f"Response content: {content}")
            
            # Additional validation
            if not content:
                raise ValueError("Empty response from OpenAI API")
                
            try:
                result = json.loads(content)
                # Validate the required fields exist
                required_fields = ["has_vulnerability", "severity", "title", 
                                "description", "impact", "recommendation", "evidence"]
                if not all(field in result for field in required_fields):
                    raise ValueError("Missing required fields in response")
                    
                return result
            except json.JSONDecodeError as je:
                logger.error(f"Invalid JSON response: {content}")
                return self._fallback_analysis(api_data)
                
        except Exception as e:
            logger.error(f"Error in ChatGPT analysis: {str(e)}")
            return self._fallback_analysis(api_data)
    
    def _fallback_analysis(self, api_data: Dict) -> Dict:
        """Fallback analysis when ChatGPT is unavailable"""
        auth = json.loads(api_data.get('authorization', '{}'))
        headers = json.loads(api_data.get('headers', '{}'))
        
        has_auth_header = any(key.lower() in ['authorization', 'x-api-key', 'api-key'] 
                             for key in headers.keys())
        
        auth_type = auth.get('type', 'noauth')
        
        if auth_type == 'noauth' and not has_auth_header:
            return {
                "has_vulnerability": True,
                "severity": "high",
                "title": "Missing Authentication on API Endpoint",
                "description": f"The API endpoint {api_data.get('name')} does not have any authentication mechanism configured.",
                "impact": "Unauthorized access to sensitive data or functionality",
                "recommendation": "Implement proper authentication (JWT, API Keys, OAuth)",
                "evidence": f"No authorization header found. Auth type: {auth_type}"
            }
        
        return {
            "has_vulnerability": False,
            "severity": "info",
            "title": "Authentication Present",
            "description": "API has authentication configured",
            "impact": "Low security risk",
            "recommendation": "Continue monitoring",
            "evidence": "Authentication headers detected"
        }

class APISecurityScannerTC1:
    """Main service for API security scanning"""
    
    def __init__(self, user):
        self.user = user
        self.data_service = APIOrchDataServiceTC1()
        self.analyzer = VulnerabilityAnalyzerTC1()
    
    @transaction.atomic
    def initiate_scan(self, scan_id: int, scan_config: Dict = None) -> Dict:
        """Initiate a security scan for the given scan_id"""
        try:
            # Get APIs for the scan
            apis = self.data_service.get_apis_by_scan_id(scan_id)
            
            if not apis:
                return {"error": "No APIs found for the given scan_id", "success": False}
            
            # Get existing session
            session = ScanSessionTC1.objects.get(scan_id=scan_id)
            session.status = 'scanning'
            session.save()
            
            # Start scanning APIs
            self._scan_apis(apis, scan_id)
            
            # Update session status
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()
            
            # Generate vulnerability summary
            self._generate_vulnerability_summary(scan_id)
            
            return {
                "message": "Scan completed successfully",
                "scan_id": scan_id,
                "total_apis": len(apis),
                "session_id": session.id,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error in scan execution: {str(e)}")
            # Update session to failed
            try:
                session = ScanSessionTC1.objects.get(scan_id=scan_id)
                session.status = 'failed'
                session.completed_at = timezone.now()
                session.save()
            except:
                pass
            return {"error": str(e), "success": False}

    def _scan_apis(self, apis: List[Dict], scan_id: int):
        """Scan individual APIs for vulnerabilities"""
        session = ScanSessionTC1.objects.get(scan_id=scan_id)
        
        for api in apis:
            try:
                # Analyze for authentication vulnerabilities
                analysis = self.analyzer.analyze_authentication_vulnerability(api)
                
                if analysis.get('has_vulnerability', False):
                    # Create scan result
                    scan_result = ScanResultTC1.objects.create(
                        scan_id=scan_id,
                        api_id=api['id'],
                        api_name=api['name'],
                        api_method=api['method'],
                        api_url=api['url'],
                        vulnerability_type='weak_auth',
                        severity=analysis['severity'],
                        status='completed',
                        title=analysis['title'],
                        description=analysis['description'],
                        impact=analysis['impact'],
                        recommendation=analysis['recommendation'],
                        evidence=analysis['evidence'],
                        scan_completed_at=timezone.now(),
                        created_by=self.user
                    )
                    
                    session.vulnerabilities_found += 1
                
                session.completed_apis += 1
                session.save()
                
            except Exception as e:
                logger.error(f"Error scanning API {api['id']}: {str(e)}")
                session.failed_apis += 1
                session.save()
    
    def _generate_vulnerability_summary(self, scan_id: int):
        """Generate vulnerability summary for the scan"""
        # Clear existing summary
        VulnerabilitySummaryTC1.objects.filter(scan_id=scan_id).delete()
        
        # Get vulnerability counts by type and severity        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT "vulnerability_type", "severity", COUNT(*) as count
                FROM api2_scan_results 
                WHERE "scan_id" = %s
                GROUP BY "vulnerability_type", "severity"
            """, [scan_id])
            
            for row in cursor.fetchall():
                VulnerabilitySummaryTC1.objects.create(
                    scan_id=scan_id,
                    vulnerability_type=row[0],
                    severity=row[1],
                    count=row[2]
                )
    
    def get_scan_results(self, filters: Dict = None) -> Dict:
        """Get scan results with optional filters"""
        queryset = ScanResultTC1.objects.all().order_by('-scan_started_at')
        
        if filters:
            if filters.get('scan_id'):
                queryset = queryset.filter(scan_id=filters['scan_id'])
            if filters.get('vulnerability_type'):
                queryset = queryset.filter(vulnerability_type=filters['vulnerability_type'])
            if filters.get('severity'):
                queryset = queryset.filter(severity=filters['severity'])
            if filters.get('status'):
                queryset = queryset.filter(status=filters['status'])
            if filters.get('api_method'):
                queryset = queryset.filter(api_method__icontains=filters['api_method'])
            if filters.get('date_from'):
                queryset = queryset.filter(scan_started_at__gte=filters['date_from'])
            if filters.get('date_to'):
                queryset = queryset.filter(scan_started_at__lte=filters['date_to'])
        
        return queryset
    
    def get_scan_stats(self) -> Dict:
        """Get overall scan statistics"""
        
        sessions = ScanSessionTC1.objects.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(status__in=['pending', 'scanning'])),
            completed=Count('id', filter=Q(status='completed')),
            failed=Count('id', filter=Q(status='failed'))
        )
        
        vulnerabilities = ScanResultTC1.objects.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low'))
        )
        
        return {
            'total_scans': sessions['total'],
            'active_scans': sessions['active'],
            'completed_scans': sessions['completed'],
            'failed_scans': sessions['failed'],
            'total_vulnerabilities': vulnerabilities['total'],
            'critical_vulnerabilities': vulnerabilities['critical'],
            'high_vulnerabilities': vulnerabilities['high'],
            'medium_vulnerabilities': vulnerabilities['medium'],
            'low_vulnerabilities': vulnerabilities['low']
        }