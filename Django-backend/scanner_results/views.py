from django.db import connections
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import ProbeControlMapping
from .serializers import ProbeControlMappingSerializer
from scanner.models import OpenAIDB, AzureDB, ScanResult
from django.db.models import Count
from django.http import HttpResponse
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import os
import tempfile
import textwrap
import uuid
import io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import urlsafe_b64encode
import secrets
import json
from datetime import datetime
from django.core.files.storage import default_storage
from django.conf import settings
import zipfile

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
            scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
            
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
            scan = AzureDB.objects.get(id=scan_id, user=request.user)
            
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
        scans = OpenAIDB.objects.filter(user=request.user).order_by('-created_at')
        
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
        scans = AzureDB.objects.filter(user=request.user).order_by('-created_at')
        
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
            scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
            
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
            scan = AzureDB.objects.get(id=scan_id, user=request.user)
            
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
            scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
            
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
            scan = AzureDB.objects.get(id=scan_id,user=request.user)
            
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
        
    def _generate_artifact_file(self, prompt, output, scan_type, scan_name, probe_name, finding_index):
        """
        Generate a text file containing prompt and output
        """
        # Clean probe name for filename safety
        clean_probe = probe_name.replace(" ", "_").replace("/", "_")[:100]
        
        # Generate filename
        file_name = f"Test_Scan_{scan_type}_Finding_{finding_index}_{clean_probe}.txt"
            
        # Create content
        content = f"PROBE: {probe_name}\n"
        content += f"PROMPT:\n{'-'*80}\n{prompt}\n\n"
        content += f"OUTPUT:\n{'-'*80}\n{output}"
        
        # Save to temporary file
        artifact_path = os.path.join(settings.MEDIA_ROOT, 'artifacts', file_name)
        os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
        
        with open(artifact_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return file_name
    
    # def _encrypt_file(self, file_data):
    #     """
    #     Encrypt file data using AES-256-GCM
    #     Returns: encrypted data, key, and nonce
    #     """
    #     # Generate a random encryption key (32 bytes for AES-256)
    #     key = secrets.token_bytes(32)
        
    #     # Generate a nonce
    #     nonce = secrets.token_bytes(12)
        
    #     # Create an AES-GCM cipher instance
    #     aesgcm = AESGCM(key)
        
    #     # Encrypt the data
    #     encrypted_data = aesgcm.encrypt(nonce, file_data, None)
        
    #     # Return encrypted data along with key and nonce for decryption
    #     return encrypted_data, key, nonce
    
    def _create_excel_workbook(self, results, scan_name, client_name, client_app_name, scan_type):
        """
        Create an Excel workbook with the scan results
        """
        wb = Workbook()
        ws = wb.active
        
        # Set sheet name based on scan details
        ws.title = f"{scan_name}_{client_name}_{client_app_name}"[:31]  # Sheet name length limit
        
        # Define column headings
        headers = [
            "Sr. No.", "Control Title", "Control Description", 
            "Control Observation", "Control Impact", "Control Recommendation", 
            "Severity", "Tester Comments", "Tester Artifacts", 
            "Affected Device", "Asset Tag", "Category Tag", 
            "OWASP/MITRE", "Findings Owner Email", "CVE ID", "CWE ID"
        ]
        
        # Define column widths
        column_widths = {
            "A": 8, "B": 30, "C": 40, "D": 40, "E": 40, 
            "F": 40, "G": 15, "H": 25, "I": 25, "J": 20, 
            "K": 15, "L": 15, "M": 30, "N": 25, "O": 15, "P": 15
        }
        
        # Set column widths
        for col, width in column_widths.items():
            ws.column_dimensions[col].width = width
        
        # Define styles
        header_fill = PatternFill(start_color="000080", end_color="000080", fill_type="solid")  # Dark Blue
        header_font = Font(color="FFFFFF", bold=True)  # White, Bold
        wrap_alignment = Alignment(wrap_text=True, vertical="top")
        border = Border(
            left=Side(style='thin'), 
            right=Side(style='thin'), 
            top=Side(style='thin'), 
            bottom=Side(style='thin')
        )
        
        # Write headers
        for col_num, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_num, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = border
        
        # Write data rows
        artifact_files = []
        for row_num, result in enumerate(results, 2):
            # Generate artifact file with consistent naming
            if result.get('prompt') and result.get('output'):
                probe_name = result.get('probe', 'unknown_probe')
                finding_index = row_num - 1  # Matches Excel's "Sr. No." column
                artifact_filename = self._generate_artifact_file(
                    prompt=result.get('prompt', ''),
                    output=result.get('output', ''),
                    scan_type=scan_type.capitalize(),  # "Azure" or "OpenAI"
                    scan_name=scan_name,
                    probe_name=probe_name,
                    finding_index=row_num - 1
                )
                artifact_files.append(artifact_filename)
            
            # Combine OWASP and MITRE values
            owasp_mitre = []
            if result.get('owasp_top_10_for_llms'):
                owasp_mitre.append(result.get('owasp_top_10_for_llms'))
            if result.get('mitre_atlas'):
                owasp_mitre.append(result.get('mitre_atlas'))
            owasp_mitre_value = "; ".join(owasp_mitre)
            
            # Row data
            row_data = [
                row_num - 1,  # Sr. No.
                result.get('control_title', ''),
                result.get('control_description', ''),
                result.get('control_observation', ''),
                result.get('control_impact', ''),
                result.get('control_recommendation', ''),
                result.get('severity', ''),
                '',  # Tester Comments (blank)
                artifact_filename if 'artifact_filename' in locals() else '',  # Tester Artifacts
                result.get('client_app_name', ''),
                '',  # Asset Tag (blank)
                'Application',  # Category Tag (constant)
                owasp_mitre_value,
                '',  # Findings Owner Email (blank)
                '',  # CVE ID (blank)
                ''   # CWE ID (blank)
            ]
            
            # Write row data
            for col_num, value in enumerate(row_data, 1):
                cell = ws.cell(row=row_num, column=col_num, value=value)
                cell.alignment = wrap_alignment
                cell.border = border
        
        return wb, artifact_files
    
    # def _store_encryption_info(self, filename, key, nonce):
    #     """
    #     Store encryption key and nonce (securely)
    #     In production, you would want to store these in a secure database or KMS
    #     """
    #     # Convert binary key and nonce to base64 for storage
    #     key_b64 = urlsafe_b64encode(key).decode('utf-8')
    #     nonce_b64 = urlsafe_b64encode(nonce).decode('utf-8')
        
    #     # Create encryption info object
    #     encryption_info = {
    #         'filename': filename,
    #         'key': key_b64,
    #         'nonce': nonce_b64,
    #         'timestamp': datetime.now().isoformat()
    #     }
        
    #     # In a real-world application, you would store this information securely
    #     # For this example, we'll store it in a JSON file (not recommended for production)
    #     info_path = os.path.join(settings.MEDIA_ROOT, 'encryption_keys', f"{filename}.key")
    #     os.makedirs(os.path.dirname(info_path), exist_ok=True)
        
    #     with open(info_path, 'w') as f:
    #         json.dump(encryption_info, f)
        
    #     return True
    
    @action(detail=False, methods=['get'])
    def download_openai_report(self, request):
        """
        Generate and download an Excel report for OpenAI scan results
        """
        scan_id = request.query_params.get('id')
        
        if not scan_id:
            return Response({"error": "id parameter is required"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get the OpenAIDB scan
            scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
            
            # Get all results for this scan with control mappings
            results = []
            scan_results = ScanResult.objects.filter(openai_scan=scan)
            
            for result in scan_results:
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
                
                results.append(result_data)
            
            # Create Excel workbook
            wb, artifact_files = self._create_excel_workbook(
                results, 
                scan.scan_name, 
                scan.client_name, 
                scan.client_app_name,
                'openai'
            )
            
            # Save workbook to bytes buffer
            buffer = io.BytesIO()
            wb.save(buffer)
            buffer.seek(0)
            file_data = buffer.getvalue()
            
            # Encrypt the file
            encrypted_data, key, nonce = self._encrypt_file(file_data)
            
            # Generate a unique filename
            filename = f"OpenAI_Scan_{scan.scan_name}_{scan.client_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"
            filename = filename.replace(' ', '_')
            
            # Store encryption info for later retrieval
            self._store_encryption_info(filename, key, nonce)
            
            # Create HTTP response with encrypted data
            response = HttpResponse(
                encrypted_data,
                content_type='application/vnd.ms-excel'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            # Add encryption headers with key and nonce
            # In production, you would handle this differently for better security
            response['X-Encryption-Key'] = urlsafe_b64encode(key).decode('utf-8')
            response['X-Encryption-Nonce'] = urlsafe_b64encode(nonce).decode('utf-8')
            
            return response
            
        except OpenAIDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def download_azure_report(self, request):
        """
        Generate and download an Excel report for Azure scan results
        """
        scan_id = request.query_params.get('id')
        
        if not scan_id:
            return Response({"error": "id parameter is required"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get the AzureDB scan
            scan = AzureDB.objects.get(id=scan_id, user=request.user)
            
            # Get all results for this scan with control mappings
            results = []
            scan_results = ScanResult.objects.filter(azure_scan=scan)
            
            for result in scan_results:
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
                
                results.append(result_data)
            
            # Create Excel workbook
            wb, artifact_files = self._create_excel_workbook(
                results, 
                scan.scan_name, 
                scan.client_name, 
                scan.client_app_name,
                'azure'
            )
            
            # Save workbook to bytes buffer
            buffer = io.BytesIO()
            wb.save(buffer)
            buffer.seek(0)
            file_data = buffer.getvalue()
            
            # Encrypt the file
            encrypted_data, key, nonce = self._encrypt_file(file_data)
            
            # Generate a unique filename
            filename = f"Azure_Scan_{scan.scan_name}_{scan.client_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"
            filename = filename.replace(' ', '_')
            
            # Store encryption info for later retrieval
            self._store_encryption_info(filename, key, nonce)
            
            # Create HTTP response with encrypted data
            response = HttpResponse(
                encrypted_data,
                content_type='application/vnd.ms-excel'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            # Add encryption headers with key and nonce
            # In production, you would handle this differently for better security
            response['X-Encryption-Key'] = urlsafe_b64encode(key).decode('utf-8')
            response['X-Encryption-Nonce'] = urlsafe_b64encode(nonce).decode('utf-8')
            
            return response
            
        except AzureDB.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    
    # @action(detail=False, methods=['get'])
    # def download_encrypted_zip(self, request):
    #     """
    #     Generate and download a ZIP file containing the Excel report and 
    #     all related artifact text files, encrypted with AES-256-GCM
    #     """
    #     scan_id = request.query_params.get('id')
    #     scan_type = request.query_params.get('type')  # 'openai' or 'azure'
        
    #     if not scan_id or not scan_type:
    #         return Response(
    #             {"error": "Both 'id' and 'type' parameters are required"}, 
    #             status=status.HTTP_400_BAD_REQUEST
    #         )
        
    #     if scan_type not in ['openai', 'azure']:
    #         return Response(
    #             {"error": "Type parameter must be 'openai' or 'azure'"}, 
    #             status=status.HTTP_400_BAD_REQUEST
    #         )
        
    #     try:
    #         # Get the scan and its results based on type
    #         if scan_type == 'openai':
    #             scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
    #             scan_results = ScanResult.objects.filter(openai_scan=scan)
    #             scan_model = scan.model_name
    #         else:  # azure
    #             scan = AzureDB.objects.get(id=scan_id, user=request.user)
    #             scan_results = ScanResult.objects.filter(azure_scan=scan)
    #             scan_model = scan.azure_model_name
            
    #         # Get all results with control mappings
    #         results = []
    #         artifact_files = []
            
    #         for result in scan_results:
    #             result_data = {
    #                 "scan_name": scan.scan_name,
    #                 "client_name": scan.client_name,
    #                 "client_app_name": scan.client_app_name,
    #                 "model_name": scan_model,
    #                 "probe": result.probe,
    #                 "prompt": result.prompt,
    #                 "output": result.output,
    #                 "score": result.score,
    #             }
                
    #             # Generate artifact file for this result
    #             if result.prompt and result.output:
    #                 probe_name = result.probe or 'unknown_probe'
    #                 artifact_filename = self._generate_artifact_file(
    #                     result.prompt, 
    #                     result.output,
    #                     scan.scan_name,
    #                     probe_name
    #                 )
    #                 artifact_files.append(artifact_filename)
    #                 result_data['artifact_filename'] = artifact_filename
                
    #             # Get control mapping information
    #             try:
    #                 if result.probe:
    #                     control = ProbeControlMapping.objects.get(probe_name=result.probe)
    #                     result_data.update({
    #                         "control_title": control.control_title,
    #                         "control_category": control.control_category,
    #                         "control_description": control.control_description,
    #                         "control_observation": control.control_observation,
    #                         "control_impact": control.control_impact,
    #                         "control_recommendation": control.control_recommendation,
    #                         "severity": control.severity,
    #                         "owasp_top_10_for_llms": control.owasp_top_10_for_llms,
    #                         "mitre_atlas": control.mitre_atlas,
    #                     })
    #             except ProbeControlMapping.DoesNotExist:
    #                 # No mapping found for this probe
    #                 result_data.update({
    #                     "control_title": None,
    #                     "control_category": None,
    #                     "control_description": None,
    #                     "control_observation": None,
    #                     "control_impact": None,
    #                     "control_recommendation": None,
    #                     "severity": None,
    #                     "owasp_top_10_for_llms": None,
    #                     "mitre_atlas": None,
    #                 })
                
    #             results.append(result_data)
            
    #         # Create Excel workbook
    #         wb, _ = self._create_excel_workbook(
    #             results, 
    #             scan.scan_name, 
    #             scan.client_name, 
    #             scan.client_app_name,
    #             scan_type
    #         )
            
    #         # Create a temporary directory to store files for zipping
    #         with tempfile.TemporaryDirectory() as temp_dir:
    #             # Save Excel file to temporary directory
    #             excel_filename = f"{scan_type.capitalize()}_Scan_{scan.scan_name}_{scan.client_name}.xlsx"
    #             excel_filepath = os.path.join(temp_dir, excel_filename)
    #             wb.save(excel_filepath)
                
    #             # Copy all artifact files to temporary directory
    #             artifact_dir = os.path.join(settings.MEDIA_ROOT, 'artifacts')
    #             for artifact in artifact_files:
    #                 src_path = os.path.join(artifact_dir, artifact)
    #                 if os.path.exists(src_path):
    #                     with open(src_path, 'rb') as src_file:
    #                         with open(os.path.join(temp_dir, artifact), 'wb') as dst_file:
    #                             dst_file.write(src_file.read())
                
    #             # Create a zip file
    #             zip_buffer = io.BytesIO()
    #             with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
    #                 # Add Excel file to zip
    #                 zip_file.write(excel_filepath, excel_filename)
                    
    #                 # Add all artifact files to zip
    #                 for artifact in artifact_files:
    #                     artifact_path = os.path.join(temp_dir, artifact)
    #                     if os.path.exists(artifact_path):
    #                         zip_file.write(artifact_path, os.path.join('artifacts', artifact))
                
    #             # Get zip file contents
    #             zip_buffer.seek(0)
    #             zip_data = zip_buffer.getvalue()
                
    #             # Encrypt the zip data with AES-256-GCM
    #             encrypted_data, key, nonce = self._encrypt_file(zip_data)
                
    #             # Generate a unique filename
    #             timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    #             filename = f"{scan_type.capitalize()}_Scan_{scan.scan_name}_{scan.client_name}_{timestamp}.zip"
    #             filename = filename.replace(' ', '_')
                
    #             # Store encryption info for later retrieval
    #             self._store_encryption_info(filename, key, nonce)
                
    #             # Create HTTP response with encrypted data
    #             response = HttpResponse(
    #                 encrypted_data,
    #                 content_type='application/zip'
    #             )
    #             response['Content-Disposition'] = f'attachment; filename="{filename}"'
                
    #             # Add encryption headers with key and nonce
    #             # In production, you should use a more secure method to share the key and nonce
    #             response['X-Encryption-Key'] = urlsafe_b64encode(key).decode('utf-8')
    #             response['X-Encryption-Nonce'] = urlsafe_b64encode(nonce).decode('utf-8')
                
    #             return response
                
    #     except (OpenAIDB.DoesNotExist, AzureDB.DoesNotExist):
    #         return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    #     except Exception as e:
    #         return Response(
    #             {"error": f"An error occurred: {str(e)}"}, 
    #             status=status.HTTP_500_INTERNAL_SERVER_ERROR
    #         )
    
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
    def download_unencrypted_zip(self, request):
        """
        Generate and download an unencrypted ZIP file containing the Excel report
        and all related artifact text files
        """
        scan_id = request.query_params.get('id')
        scan_type = request.query_params.get('type')  # 'openai' or 'azure'
        
        if not scan_id or not scan_type:
            return Response(
                {"error": "Both 'id' and 'type' parameters are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if scan_type not in ['openai', 'azure']:
            return Response(
                {"error": "Type parameter must be 'openai' or 'azure'"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the scan and its results based on type
            if scan_type == 'openai':
                scan = OpenAIDB.objects.get(id=scan_id, user=request.user)
                scan_results = ScanResult.objects.filter(openai_scan=scan)
                scan_model = scan.model_name
            else:  # azure
                scan = AzureDB.objects.get(id=scan_id, user=request.user)
                scan_results = ScanResult.objects.filter(azure_scan=scan)
                scan_model = scan.azure_model_name
            
            # Get all results with control mappings
            results = []
            artifact_files = []
            
            for result in scan_results:
                result_data = {
                    "scan_name": scan.scan_name,
                    "client_name": scan.client_name,
                    "client_app_name": scan.client_app_name,
                    "model_name": scan_model,
                    "probe": result.probe,
                    "prompt": result.prompt,
                    "output": result.output,
                    "score": result.score,
                }
                
                # Generate artifact file for this result
                if result.prompt and result.output:
                    probe_name = result.probe or 'unknown_probe'
                    artifact_filename = self._generate_artifact_file(
                        prompt=result.prompt,
                        output=result.output,
                        scan_type="Azure" if scan_type == "azure" else "OpenAI",
                        scan_name=scan.scan_name,
                        probe_name=result.probe or "unknown_probe",
                        finding_index=len(results) + 1  # Add finding_index parameter
                    )
                    artifact_files.append(artifact_filename)
                    result_data['artifact_filename'] = artifact_filename
                
                # Get control mapping information
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
                
                results.append(result_data)
            
            # Create Excel workbook
            wb, _ = self._create_excel_workbook(
                results, 
                scan.scan_name, 
                scan.client_name, 
                scan.client_app_name,
                scan_type
            )
            
            # Create a temporary directory to store files for zipping
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save Excel file to temporary directory
                excel_filename = f"{scan_type.capitalize()}_Scan_{scan.scan_name}_{scan.client_name}.xlsx"
                excel_filepath = os.path.join(temp_dir, excel_filename)
                wb.save(excel_filepath)
                
                # Copy all artifact files to temporary directory
                artifact_dir = os.path.join(settings.MEDIA_ROOT, 'artifacts')
                for artifact in artifact_files:
                    src_path = os.path.join(artifact_dir, artifact)
                    if os.path.exists(src_path):
                        with open(src_path, 'rb') as src_file:
                            with open(os.path.join(temp_dir, artifact), 'wb') as dst_file:
                                dst_file.write(src_file.read())
                
                # Create a zip file
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    # Add Excel file to zip
                    zip_file.write(excel_filepath, excel_filename)
                    
                    # Add all artifact files to zip
                    for artifact in artifact_files:
                        artifact_path = os.path.join(temp_dir, artifact)
                        if os.path.exists(artifact_path):
                            zip_file.write(artifact_path, os.path.join('artifacts', artifact))
                
                # Get zip file contents
                zip_buffer.seek(0)
                zip_data = zip_buffer.getvalue()
                
                # Generate a unique filename
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                filename = f"{scan_type.capitalize()}_Scan_{scan.scan_name}_{scan.client_name}_{timestamp}.zip"
                filename = filename.replace(' ', '_')
                
                # Create HTTP response with unencrypted data
                response = HttpResponse(
                    zip_data,
                    content_type='application/zip'
                )
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                
                return response
                
        except (OpenAIDB.DoesNotExist, AzureDB.DoesNotExist):
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )