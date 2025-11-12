# threat_model/views.py

import os
import json
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.exceptions import ValidationError
from django.conf import settings  
from .models import ThreatModel, Document, History
from django.http import HttpResponse
from .methodologies.ThreatModel import export_threat_model_report
from .methodologies.pasta import generate_pasta_report_data
from .methodologies.report_generator import generate_pasta_pdf_report
from .tasks import process_threat_model_documents,correlate_threat_model
from .methodologies.ThreatModel import get_stride_threat_model_from_index
from .methodologies.dread import create_dread_assessment_prompt, get_dread_assessment
from .methodologies.attack_tree_generator import generate_attack_tree_mermaid, generate_attack_tree_pdf
from celery import chain
from .serializers import ThreatModelSerializer, HistorySerializer,ThreatModelDetailSerializer

logger = logging.getLogger(__name__)

# --- File Validation Helper ---
def validate_file(file):
    """Checks if an uploaded file meets the size and extension requirements."""
    ext = file.name.split(".")[-1].lower()
    if ext not in ["pdf", "docx", "xlsx", "xls", "png", "jpg", "jpeg","txt"]:
        raise ValidationError(f"Unsupported file type: {ext}")
    if file.size > 20 * 1024 * 1024:
        raise ValidationError(f"File too large (max 20 MB)")
def generate_dread_csv_report(dread_data):
    import csv
    from io import StringIO
    """Generates a CSV string from DREAD assessment data with detailed logging."""
    logger.info("--- [HELPER] generate_dread_csv_report function STARTED ---")
    try:
        output = StringIO()
        writer = csv.writer(output)
 
        logger.info(f"[HELPER] Received raw dread_data of type: {type(dread_data)}")
        if isinstance(dread_data, dict):
            logger.info(f"[HELPER] Top-level keys in dread_data: {list(dread_data.keys())}")
        else:
            logger.info(f"[HELPER] Raw dread_data content: {dread_data}")
 
        header = [
            "Scenario",
            "Threat Type",
            "Damage Potential",
            "Reproducibility",
            "Exploitability",
            "Affected Users",
            "Discoverability",
        ]
        writer.writerow(header)
        logger.info("[HELPER] CSV header written successfully.")
 
        # --- FIX: Handle both wrapped and unwrapped formats ---
        if isinstance(dread_data, dict):
            if "dread_assessment" in dread_data:
                assessment_data = dread_data.get("dread_assessment", {})
            elif "Risk Assessment" in dread_data:
                # Directly stored without "dread_assessment" wrapper
                assessment_data = dread_data
            else:
                assessment_data = {}
        else:
            assessment_data = {}
 
        threat_list = (
            assessment_data.get("Risk Assessment", [])
            if isinstance(assessment_data, dict)
            else []
        )
        logger.info(f"[HELPER] Extracted threat_list. Number of threats found: {len(threat_list)}")
 
        if not threat_list:
            logger.warning("[HELPER] Threat list is empty. CSV will only contain the header.")
 
        for i, threat in enumerate(threat_list):
            logger.info(f"[HELPER] Processing threat #{i+1}...")
            writer.writerow([
                threat.get("Scenario", "N/A"),
                threat.get("Threat Type", "N/A"),
                threat.get("Damage Potential", "N/A"),
                threat.get("Reproducibility", "N/A"),
                threat.get("Exploitability", "N/A"),
                threat.get("Affected Users", "N/A"),
                threat.get("Discoverability", "N/A"),
            ])
 
        csv_output = output.getvalue()
        logger.info(
            f"--- [HELPER] generate_dread_csv_report function COMPLETED successfully. "
            f"CSV length: {len(csv_output)} bytes ---"
        )
        return csv_output
    except Exception as e:
        logger.error(f"--- [HELPER] CRITICAL ERROR inside generate_dread_csv_report: {e} ---", exc_info=True)
        raise
# --- API Views ---

class CreateAssessmentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        required_fields = ["assessment_name", "app_name", "client_name"]
        for field in required_fields:
            if field not in request.data:
                return Response({"error": f"Missing required field: {field}"}, status=status.HTTP_400_BAD_REQUEST)

        if ThreatModel.objects.filter(app_name=request.data["app_name"]).exists():
            return Response({"error": f"An assessment with the app name '{request.data['app_name']}' already exists."}, status=status.HTTP_409_CONFLICT)

        data = request.data
        threat_model = ThreatModel(
            assessment_name=data.get("assessment_name"),
            app_name=data.get("app_name"),
            client_name=data.get("client_name"),
            created_by=request.user,
            description=data.get("description", ""),
            authentication_methods=data.get("authentication_methods", ""),
            is_internet_facing=str(data.get("is_internet_facing", "true")).lower() in ['true', '1'],
            handles_sensitive_data=str(data.get("handles_sensitive_data", "false")).lower() in ['true', '1'],
            data_classification=data.get("data_classification", ""),
            deployment_environment=data.get("deployment_environment", ""),
            compliance_requirements=data.get("compliance_requirements", ""),
            user_types=data.get("user_types", ""),
            third_party_integrations=data.get("third_party_integrations", ""),
            critical_assets=data.get("critical_assets", "")
        )

        tech_stack_str = data.get('technology_stack', '{}')
        try:
            threat_model.technology_stack = json.loads(tech_stack_str)
        except json.JSONDecodeError:
            return Response({"error": "Invalid JSON format for 'technology_stack'."}, status=status.HTTP_400_BAD_REQUEST)
        
        threat_model.save()
        
        files = request.FILES.getlist("files")
        saved_files = []
        if files:
            for file in files:
                try:
                    validate_file(file)
                except ValidationError as e:
                    threat_model.delete()
                    return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

                doc = Document.objects.create(
                    threat_model=threat_model,
                    file=file,
                    file_type=file.name.split(".")[-1].lower()
                )
                saved_files.append(doc.file.name)

        History.objects.create(
            user=request.user,
            threat_model=threat_model,
            action=History.ActionChoices.CREATE_ASSESSMENT,
            details={"files_uploaded": saved_files}
        )
        process_threat_model_documents.delay(threat_model.id)
        logger.info(f"Queued processing for Threat Model: {threat_model.id}")

        return Response({
            "message": "Assessment created successfully and is now being processed.",
            "id": threat_model.id,
            "files_uploaded": saved_files
        }, status=status.HTTP_201_CREATED)


class AnalyzeThreatModelView(APIView):
    """
    Triggers the AI threat model analysis for a specific assessment.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        if threat_model.status != ThreatModel.StatusChoices.COMPLETED:
             return Response({"error": f"Threat Model is not ready for analysis. Current status: {threat_model.status}"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            api_key = settings.OPENAI_API_KEY
            if not api_key:
                logger.error("OPENAI_API_KEY not configured in settings.")
                return Response({"error": "API Key not configured on the server."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            #query = f"Analyze security posture for {threat_model.app_name}"
            
            result = get_stride_threat_model_from_index(
                threat_model_id=threat_model.id,
                
                api_key=api_key,
                model_name="gpt-4.1"
            )
            History.objects.create(
                user=request.user,
                threat_model=threat_model,
                action=History.ActionChoices.RUN_STRIDE_ANALYSIS
            )
            return Response({
                "message": "Threat model analysis completed successfully.",
                "threat_model_id": threat_model.id,
                "executive_summary": result.get("executive_summary")
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Analysis failed for Threat Model {pk}: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred during analysis: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportView(APIView):
    """
    Provides the threat model report in a downloadable format (e.g., CSV).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        # Check if the analysis has been completed
        if not threat_model.threat_model_data:
            return Response({"error": "No analysis data found for this threat model. Please run the analysis first."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Determine the format from a query parameter, defaulting to csv
        report_format = request.query_params.get('format', 'csv').lower()

        if report_format not in ['csv', 'json', 'markdown']:
             return Response({"error": "Unsupported format. Please choose 'csv', 'json', or 'markdown'."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Call the existing export function from your analysis module
            report_content = export_threat_model_report(
                threat_model_id=threat_model.id,
                format=report_format
            )
            History.objects.create(
                user=request.user,
                threat_model=threat_model,
                action=History.ActionChoices.DOWNLOAD_REPORT,
                details={"format": report_format, "report_type": "STRIDE"}
            )
            if report_format == 'csv':
                # Create a proper HTTP response that triggers a file download
                response = HttpResponse(report_content, content_type='text/csv')
                response['Content-Disposition'] = f'attachment; filename="{threat_model.app_name}_threat_model.csv"'
                return response
            
            elif report_format == 'markdown':
                 return HttpResponse(report_content, content_type='text/plain')
            
            else: # JSON format
                return Response(json.loads(report_content), status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Failed to generate report for Threat Model {pk}: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred while generating the report: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class StatusView(APIView):
    """
    Checks the current status of a threat model assessment.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "threat_model_id": threat_model.id,
            "app_name": threat_model.app_name,
            "status": threat_model.status
        }, status=status.HTTP_200_OK)
    
class ReassessThreatModelView(APIView):
    """
    GET: Fetches existing threat model details for editing.
    POST: Accepts new documents and updated details for an EXISTING threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
 
    def get(self, request, pk):
        """Returns the current details of an assessment for editing."""
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
            serializer = ThreatModelDetailSerializer(threat_model)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
 
    def post(self, request, pk):
        """Updates assessment details and/or uploads new files to trigger re-processing."""
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
 
        data = request.data
        files = request.FILES.getlist("files")
 
        if not any(data) and not files:
            return Response({"error": "No data or files provided for re-assessment."}, status=status.HTTP_400_BAD_REQUEST)
 
        # --- Update ThreatModel fields ---
        threat_model.assessment_name = data.get("assessment_name", threat_model.assessment_name)
        threat_model.client_name = data.get("client_name", threat_model.client_name)
        threat_model.description = data.get("description", threat_model.description)
        threat_model.authentication_methods = data.get("authentication_methods", threat_model.authentication_methods)
        threat_model.data_classification = data.get("data_classification", threat_model.data_classification)
        threat_model.deployment_environment = data.get("deployment_environment", threat_model.deployment_environment)
        threat_model.compliance_requirements = data.get("compliance_requirements", threat_model.compliance_requirements)
        threat_model.user_types = data.get("user_types", threat_model.user_types)
        threat_model.third_party_integrations = data.get("third_party_integrations", threat_model.third_party_integrations)
        threat_model.critical_assets = data.get("critical_assets", threat_model.critical_assets)
 
        if data.get("is_internet_facing") is not None:
            threat_model.is_internet_facing = str(data.get("is_internet_facing")).lower() in ['true', '1']
        if data.get("handles_sensitive_data") is not None:
            threat_model.handles_sensitive_data = str(data.get("handles_sensitive_data")).lower() in ['true', '1']
 
        if 'technology_stack' in data:
            try:
                threat_model.technology_stack = json.loads(data.get('technology_stack'))
            except (json.JSONDecodeError, TypeError):
                 return Response({"error": "Invalid JSON format for 'technology_stack'."}, status=status.HTTP_400_BAD_REQUEST)
 
        threat_model.save()
 
        # --- Handle File Uploads ---
        saved_files = []
        if files:
            for file in files:
                try:
                    validate_file(file)
                except ValidationError as e:
                    return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
 
                doc = Document.objects.create(threat_model=threat_model, file=file, file_type=file.name.split(".")[-1].lower())
                saved_files.append(doc.file.name)
 
            History.objects.create(
                user=request.user, threat_model=threat_model,
                action=History.ActionChoices.REASSESS_MODEL,
                details={"files_uploaded": saved_files}
            )
 
            # Trigger the background processing tasks for the new files.
            workflow = chain(process_threat_model_documents.s(threat_model.id), correlate_threat_model.s())
            workflow.delay()
            logger.info(f"Queued re-assessment processing for Threat Model: {threat_model.id}")
 
            return Response({
                "message": "Assessment details updated. New files are being processed.",
                "id": threat_model.id,
                "new_files_uploaded": saved_files
            }, status=status.HTTP_200_OK)
 
        # If we are here, it means only metadata was updated, no new files.
        return Response({
            "message": "Assessment details updated successfully.",
            "id": threat_model.id,
        }, status=status.HTTP_200_OK)
        
class ThreatModelListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        Lists all threat models created by the currently authenticated user.
        """
        threat_models = ThreatModel.objects.filter(created_by=request.user)
        serializer = ThreatModelSerializer(threat_models, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DreadAssessmentView(APIView):
    """
    Triggers the DREAD risk assessment for an existing threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure a STRIDE model exists first
        if not threat_model.threat_model_data or 'threat_model' not in threat_model.threat_model_data:
            return Response({"error": "No STRIDE threat model found. Please run an analysis first."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            api_key = settings.OPENAI_API_KEY
            if not api_key:
                logger.error("OPENAI_API_KEY not configured in settings.")
                return Response({"error": "API Key not configured on the server."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Extract only the threats from the existing data
            stride_threats = threat_model.threat_model_data.get('threat_model', [])
            
            # Create the specific prompt for DREAD assessment
            prompt = create_dread_assessment_prompt(json.dumps(stride_threats, indent=2))
            
            # Call the new DREAD assessment function
            dread_result = get_dread_assessment(
                api_key=api_key,
                model_name="gpt-4.1", # Or your preferred model
                prompt=prompt
            )

            # Save the DREAD assessment results to the new field
            threat_model.dread_assessment_data = dread_result
            threat_model.save()

            History.objects.create(
                user=request.user,
                threat_model=threat_model,
                action=History.ActionChoices.RUN_DREAD_ASSESSMENT
            )
            return Response({
                "message": "DREAD risk assessment completed successfully.",
                "threat_model_id": threat_model.id,
                "dread_assessment": dread_result
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"DREAD assessment failed for Threat Model {pk}: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred during DREAD analysis: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)     

class AttackTreeView(APIView):
    """
    Handles the generation and retrieval of the standalone attack tree.
    This feature is now dependent on a completed STRIDE analysis.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        """ Retrieves an existing attack tree from its dedicated 'attack_tree_data' field. """
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
            # CHANGE: Read from the new attack_tree_data field
            if threat_model.attack_tree_data and "attack_tree_mermaid" in threat_model.attack_tree_data:
                return Response({
                    "threat_model_id": threat_model.id,
                    "attack_tree_mermaid": threat_model.attack_tree_data.get("attack_tree_mermaid")
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Attack tree has not been generated for this model yet."}, status=status.HTTP_404_NOT_FOUND)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, pk):
        """ Generates a new attack tree based on the existing STRIDE analysis results. """
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        # CHANGE: Check the new attack_tree_data field
        if threat_model.attack_tree_data:
            return Response({"message": "An attack tree already exists for this model."}, status=status.HTTP_409_CONFLICT)
            
        # CHANGE: Enforce dependency on STRIDE (threat_model_data) instead of PASTA
        if not threat_model.threat_model_data or 'threat_model' not in threat_model.threat_model_data:
            return Response({"error": "A completed STRIDE analysis is required before generating an attack tree. Please run the STRIDE analysis first."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            api_key = settings.OPENAI_API_KEY
            if not api_key:
                return Response({"error": "API Key not configured on the server."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            attack_tree_mermaid = generate_attack_tree_mermaid(api_key, "gpt-4.1", threat_model)

            if not attack_tree_mermaid or len(attack_tree_mermaid.strip()) < 100:
                return Response({"error": "Failed to generate attack tree - empty result"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # CHANGE: Save to the new attack_tree_data field
            threat_model.attack_tree_data = {"attack_tree_mermaid": attack_tree_mermaid}
            threat_model.save()
            
            History.objects.create(user=request.user, threat_model=threat_model, action=History.ActionChoices.GENERATE_ATTACK_TREE)
            
            return Response({
                "message": "Attack tree generated successfully based on STRIDE analysis.",
                "threat_model_id": threat_model.id,
                "attack_tree_mermaid": attack_tree_mermaid
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Failed to generate Attack Tree for POST request: {e}", exc_info=True)
            return Response({"error": f"Could not generate attack tree: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AttackTreeExportView(APIView):
    """
    Handles the PDF export of an existing attack tree.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        """
        Exports the existing attack tree as a PDF.
        """
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        if not threat_model.attack_tree_data or "attack_tree_mermaid" not in threat_model.attack_tree_data:
                return Response({"error": "No attack tree data found to export. Please generate one first."}, status=status.HTTP_400_BAD_REQUEST)

        attack_tree_mermaid = threat_model.attack_tree_data.get("attack_tree_mermaid")
        
        try:
            pdf_content = generate_attack_tree_pdf(threat_model, attack_tree_mermaid)
            History.objects.create(
                user=request.user,
                threat_model=threat_model,
                action=History.ActionChoices.DOWNLOAD_REPORT,
                details={"format": "pdf", "report_type": "Attack Tree"}
            )
            response = HttpResponse(pdf_content, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{threat_model.app_name}_Attack_Tree.pdf"'
            return response
        except Exception as e:
            logger.error(f"Failed to generate Attack Tree PDF for export: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred during PDF generation: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class DreadReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
 
    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
 
        dread_data = threat_model.dread_assessment_data
        logger.warning(f"[DEBUG] DREAD data type: {type(dread_data)}, content: {dread_data}")
        # Ensure dict, even if stored as string
        if isinstance(dread_data, str):
            try:
                dread_data = json.loads(dread_data)
            except Exception:
                return Response({"error": "Invalid DREAD assessment data format."}, status=500)
 
        # FIX: Only return 404 if it's empty
        if not isinstance(dread_data, dict) or not dread_data:
            return Response({
                "error": "DREAD assessment has not been performed for this model yet."
            }, status=status.HTTP_404_NOT_FOUND)
 
        report_format = request.query_params.get("format", "json").lower()
 
        if report_format == "csv":
            try:
                csv_content = generate_dread_csv_report(dread_data)
                response = HttpResponse(csv_content, content_type="text/csv")
                response["Content-Disposition"] = f'attachment; filename="{threat_model.app_name}_DREAD_Report.csv"'
                return response
            except Exception as e:
                logger.error(f"Failed to generate DREAD CSV report for TM {pk}: {e}", exc_info=True)
                return Response({"error": "Could not generate CSV report."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 
        elif report_format == "json":
            return Response({
                "threat_model_id": threat_model.id,
                "dread_assessment": dread_data
            }, status=status.HTTP_200_OK)
 
        else:
            return Response(
                {"error": "Unsupported format. Please choose 'json' or 'csv'."},
                status=status.HTTP_400_BAD_REQUEST,
            )
class AnalysisStatusView(APIView):
    """
    Checks the status of the main STRIDE analysis for a threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
        
        # This checks if the STRIDE analysis result itself is populated.
        analysis_status = "Completed" if threat_model.threat_model_data else "Not Started"

        return Response({
            "threat_model_id": threat_model.id,
            "app_name": threat_model.app_name,
            "assessment_name": threat_model.assessment_name,
            "analysis_status": analysis_status
        }, status=status.HTTP_200_OK)
        
class DreadStatusView(APIView):
    """
    Checks the status of a DREAD assessment for a threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
        
        assessment_status = "Completed" if threat_model.dread_assessment_data else "Not Started"

        return Response({
            "threat_model_id": threat_model.id,
            "app_name": threat_model.app_name,
            "assessment_name": threat_model.assessment_name,
            "dread_status": assessment_status
        }, status=status.HTTP_200_OK)

class PastaStatusView(APIView):
    """
    Checks the status of a PASTA assessment for a threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
        
        pasta_status = "Completed" if threat_model.pasta_assessment_data else "Not Started"

        return Response({
            "threat_model_id": threat_model.id,
            "app_name": threat_model.app_name,
            "assessment_name": threat_model.assessment_name,
            "pasta_status": pasta_status
        }, status=status.HTTP_200_OK)

class AttackTreeStatusView(APIView):
    """
    Checks the status of an Attack Tree generation for a threat model.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
        
        # The attack tree is stored within the PASTA assessment data
        attack_status = "Completed" if threat_model.attack_tree_data else "Not Started"

        return Response({
            "threat_model_id": threat_model.id,
            "app_name": threat_model.app_name,
            "assessment_name": threat_model.assessment_name,
            "attack_tree_status": attack_status
        }, status=status.HTTP_200_OK)
    
class PastaAssessmentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        """
        Retrieves the saved PASTA assessment data as JSON. (No changes needed here)
        """
        # ... this method is already correct ...
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        if not threat_model.pasta_assessment_data:
            return Response({
                "error": "PASTA assessment has not been performed for this model yet."
            }, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "threat_model_id": threat_model.id,
            "pasta_assessment_data": threat_model.pasta_assessment_data
        }, status=status.HTTP_200_OK)

    def post(self, request, pk):
        """
        Generates (or re-generates) the PASTA assessment data and saves it.
        This no longer returns a PDF.
        """
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        try:
            api_key = settings.OPENAI_API_KEY
            context = threat_model.get_context_summary()

            # 1. Generate all the data for the PASTA report.
            full_pasta_data = generate_pasta_report_data(
                api_key=api_key,
                model_name="gpt-4.1",
                context=context
            )

            # 2. Save the complete data object to the database.
            threat_model.pasta_assessment_data = full_pasta_data
            threat_model.save()
            
            History.objects.create(
                user=request.user,
                threat_model=threat_model,
                action=History.ActionChoices.RUN_PASTA_ASSESSMENT
            )
            
            # 3. Return the JSON data, NOT a PDF.
            return Response({
                "message": "PASTA assessment data generated successfully.",
                "threat_model_id": threat_model.id,
                "pasta_assessment_data": full_pasta_data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"PASTA assessment failed for Threat Model {pk}: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred during PASTA analysis: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class PastaExportView(APIView):
    """
    Handles the PDF export of an existing PASTA assessment.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        """
        Creates a PDF report from existing PASTA data in the database.
        """
        try:
            threat_model = ThreatModel.objects.get(pk=pk, created_by=request.user)
        except ThreatModel.DoesNotExist:
            return Response({"error": "Threat Model not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        # 1. Check if the data exists in the database.
        if not threat_model.pasta_assessment_data:
            return Response({
                "error": "PASTA assessment data not found. Please generate it first by sending a POST request to /pasta-assess/."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 2. Retrieve the existing data.
            pasta_data = threat_model.pasta_assessment_data

            # 3. Generate the PDF file from this data.
            pdf_content = generate_pasta_pdf_report(threat_model, pasta_data)

            # 4. Return the generated PDF as a downloadable file.
            response = HttpResponse(pdf_content, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{threat_model.app_name}_PASTA_Report.pdf"'
            return response

        except Exception as e:
            logger.error(f"PASTA PDF export failed for Threat Model {pk}: {e}", exc_info=True)
            return Response({"error": f"An unexpected error occurred during PDF generation: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class HistoryListView(APIView):
    """
    Retrieves the action history for the currently authenticated user.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        history_events = History.objects.filter(user=request.user)
        serializer = HistorySerializer(history_events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

