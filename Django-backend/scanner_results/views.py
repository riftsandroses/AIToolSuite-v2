from django.db import connections
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import ProbeControlMapping
from .serializers import ProbeControlMappingSerializer
from scanner.models import OpenAIDB, AzureDB, ScanResult

class ProbeControlMappingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing the probe control mappings
    """
    queryset = ProbeControlMapping.objects.all()
    serializer_class = ProbeControlMappingSerializer
    permission_classes = [permissions.IsAuthenticated]


class ScanResultsViewSet(viewsets.ViewSet):
    """
    ViewSet for retrieving scan results with associated control information
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def by_openai_scan(self, request):
        """
        Get scan results for a specific OpenAI scan
        """
        scan_id = request.query_params.get('id')
        
        if not scan_id:
            return Response({"error": "id parameter is required"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get the OpenAIDB scan
            scan = OpenAIDB.objects.get(id=scan_id)
            
            # Get all results for this scan
            results = ScanResult.objects.filter(openai_scan=scan)
            
            # Format the results with control mapping info
            formatted_results = []
            for result in results:
                result_data = {
                    "scan_name": scan.scan_name,
                    "client_name": scan.client_name,
                    "client_app_name": scan.client_app_name,
                    "model_name": scan.model_name,
                    "probe": result.probe,
                    "prompt": result.prompt,
                    "output": result.output,
                    "score": result.score,
                }
                
                # Get control mapping information for this probe
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        result_data.update({
                            "control_title": control.control_title,
                            "control_description": control.control_description,
                            "control_observation": control.control_observation,
                            "control_impact": control.control_impact,
                            "control_recommendation": control.control_recommendation,
                            "severity": control.severity,
                            "owasp_top_10_for_llms": control.owasp_top_10_for_llms,
                            "mitre_atlas": control.mitre_atlas,
                        })
                except ProbeControlMapping.DoesNotExist:
                    # No mapping found for this probe
                    result_data.update({
                        "control_title": None,
                        "control_description": None,
                        "control_observation": None,
                        "control_impact": None,
                        "control_recommendation": None,
                        "severity": None,
                        "owasp_top_10_for_llms": None,
                        "mitre_atlas": None,
                    })
                
                formatted_results.append(result_data)
            
            return Response(formatted_results)
            
        except OpenAIDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def by_azure_scan(self, request):
        """
        Get scan results for a specific Azure scan
        """
        scan_id = request.query_params.get('id')
        
        if not scan_id:
            return Response({"error": "id parameter is required"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get the AzureDB scan
            scan = AzureDB.objects.get(id=scan_id)
            
            # Get all results for this scan
            results = ScanResult.objects.filter(azure_scan=scan)
            
            # Format the results with control mapping info
            formatted_results = []
            for result in results:
                result_data = {
                    "scan_name": scan.scan_name,
                    "client_name": scan.client_name,
                    "client_app_name": scan.client_app_name,
                    "azure_model_name": scan.azure_model_name,
                    "azure_deployment_name": scan.azure_deployment_name,
                    "probe": result.probe,
                    "prompt": result.prompt,
                    "output": result.output,
                    "score": result.score,
                }
                
                # Get control mapping information for this probe
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        result_data.update({
                            "control_title": control.control_title,
                            "control_description": control.control_description,
                            "control_observation": control.control_observation,
                            "control_impact": control.control_impact,
                            "control_recommendation": control.control_recommendation,
                            "severity": control.severity,
                            "owasp_top_10_for_llms": control.owasp_top_10_for_llms,
                            "mitre_atlas": control.mitre_atlas,
                        })
                except ProbeControlMapping.DoesNotExist:
                    # No mapping found for this probe
                    result_data.update({
                        "control_title": None,
                        "control_description": None,
                        "control_observation": None,
                        "control_impact": None,
                        "control_recommendation": None,
                        "severity": None,
                        "owasp_top_10_for_llms": None,
                        "mitre_atlas": None,
                    })
                
                formatted_results.append(result_data)
            
            return Response(formatted_results)
            
        except AzureDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def all_openai_scans(self, request):
        """
        Get a list of all OpenAI scans
        """
        scans = OpenAIDB.objects.all().order_by('-created_at')
        
        scan_list = []
        for scan in scans:
            scan_list.append({
                "id": scan.id,
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "client_app_name": scan.client_app_name,
                "model_name": scan.model_name,
                "created_at": scan.created_at,
            })
        
        return Response({"scans": scan_list})
    
    @action(detail=False, methods=['get'])
    def all_azure_scans(self, request):
        """
        Get a list of all Azure scans
        """
        scans = AzureDB.objects.all().order_by('-created_at')
        
        scan_list = []
        for scan in scans:
            scan_list.append({
                "id": scan.id,
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "client_app_name": scan.client_app_name,
                "azure_model_name": scan.azure_model_name,
                "azure_deployment_name": scan.azure_deployment_name,
                "created_at": scan.created_at,
            })
        
        return Response({"scans": scan_list})