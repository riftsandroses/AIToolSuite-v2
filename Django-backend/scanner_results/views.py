from django.db import connections
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import ProbeControlMapping
from .serializers import ProbeControlMappingSerializer
from scanner.models import OpenAIDB, AzureDB, ScanResult
from django.db.models import Count

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
                            "control_category": control.control_category,
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
                        "control_category": None,
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
                            "control_category": control.control_category,
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
                        "control_category": None,
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
    
    @action(detail=False, methods=['get'])
    def severity_counts_openai(self, request):
        """
        Get severity counts for a specific OpenAI scan
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
            
            # Initialize counts
            severity_counts = {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0
            }
            
            # Count severities
            for result in results:
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        if control.severity:
                            severity = control.severity.capitalize()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            else:
                                severity_counts["Unknown"] += 1
                        else:
                            severity_counts["Unknown"] += 1
                except ProbeControlMapping.DoesNotExist:
                    severity_counts["Unknown"] += 1
            
            # Format for graph
            graph_data = [
                {"severity": "High", "count": severity_counts["High"]},
                {"severity": "Medium", "count": severity_counts["Medium"]},
                {"severity": "Low", "count": severity_counts["Low"]}
            ]
            
            # Only include Unknown if there are any
            if severity_counts["Unknown"] > 0:
                graph_data.append({"severity": "Unknown", "count": severity_counts["Unknown"]})
            
            return Response({
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "severity_data": graph_data
            })
            
        except OpenAIDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def severity_counts_azure(self, request):
        """
        Get severity counts for a specific Azure scan
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
            
            # Initialize counts
            severity_counts = {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0
            }
            
            # Count severities
            for result in results:
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        if control.severity:
                            severity = control.severity.capitalize()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            else:
                                severity_counts["Unknown"] += 1
                        else:
                            severity_counts["Unknown"] += 1
                except ProbeControlMapping.DoesNotExist:
                    severity_counts["Unknown"] += 1
            
            # Format for graph
            graph_data = [
                {"severity": "High", "count": severity_counts["High"]},
                {"severity": "Medium", "count": severity_counts["Medium"]},
                {"severity": "Low", "count": severity_counts["Low"]}
            ]
            
            # Only include Unknown if there are any
            if severity_counts["Unknown"] > 0:
                graph_data.append({"severity": "Unknown", "count": severity_counts["Unknown"]})
            
            return Response({
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "severity_data": graph_data
            })
            
        except AzureDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        
    @action(detail=False, methods=['get'])
    def category_distribution_openai(self, request):
        """
        Get control category distribution for a specific OpenAI scan
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
            
            # Count categories
            category_counts = {}
            total_with_category = 0
            
            for result in results:
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        if control.control_category:
                            category = control.control_category
                            if category in category_counts:
                                category_counts[category] += 1
                            else:
                                category_counts[category] = 1
                            total_with_category += 1
                except ProbeControlMapping.DoesNotExist:
                    continue
            
            # Calculate percentages and format for graph
            category_data = []
            for category, count in category_counts.items():
                percentage = round((count / total_with_category * 100), 1) if total_with_category > 0 else 0
                category_data.append({
                    "category": category,
                    "count": count,
                    "percentage": percentage
                })
            
            # Sort by count in descending order
            category_data = sorted(category_data, key=lambda x: x["count"], reverse=True)
            
            return Response({
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "total_vulnerabilities": total_with_category,
                "category_data": category_data
            })
            
        except OpenAIDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'])
    def category_distribution_azure(self, request):
        """
        Get control category distribution for a specific Azure scan
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
            
            # Count categories
            category_counts = {}
            total_with_category = 0
            
            for result in results:
                try:
                    if result.probe:
                        control = ProbeControlMapping.objects.get(probe_name=result.probe)
                        if control.control_category:
                            category = control.control_category
                            if category in category_counts:
                                category_counts[category] += 1
                            else:
                                category_counts[category] = 1
                            total_with_category += 1
                except ProbeControlMapping.DoesNotExist:
                    continue
            
            # Calculate percentages and format for graph
            category_data = []
            for category, count in category_counts.items():
                percentage = round((count / total_with_category * 100), 1) if total_with_category > 0 else 0
                category_data.append({
                    "category": category,
                    "count": count,
                    "percentage": percentage
                })
            
            # Sort by count in descending order
            category_data = sorted(category_data, key=lambda x: x["count"], reverse=True)
            
            return Response({
                "scan_name": scan.scan_name,
                "client_name": scan.client_name,
                "total_vulnerabilities": total_with_category,
                "category_data": category_data
            })
            
        except AzureDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)