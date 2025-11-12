# threat_model/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # GET /assessments/
    # Retrieves a list of all threat model assessments created by the authenticated user.
    path("assessments/", views.ThreatModelListView.as_view(), name="list-assessments"),

    # POST /create-assessment/
    # Creates a new threat model assessment. This single endpoint handles initial context data
    # (like app_name, description) and file uploads, then queues a background task for processing.
    path("create-assessment/", views.CreateAssessmentView.as_view(), name="create-full-assessment"),
    
    # POST /analyze/<int:pk>/
    # Triggers the AI-powered STRIDE analysis for a specific, processed threat model.
    # Requires the document processing to be 'COMPLETED'.
    path("analyze/<int:pk>/", views.AnalyzeThreatModelView.as_view(), name="analyze-threat-model"),
    
    # POST /reassess/<int:pk>/
    # Uploads new documents to an existing threat model and triggers a new processing and
    # correlation task to update the model.
    path("reassess/<int:pk>/", views.ReassessThreatModelView.as_view(), name="reassess-threat-model"),
    
    # POST /dread-assess/<int:pk>/
    # Triggers a DREAD risk assessment for a threat model that already has a STRIDE analysis.
    path("dread-assess/<int:pk>/", views.DreadAssessmentView.as_view(), name="dread-assess-model"),
    
    # GET, POST /pasta-assess/<int:pk>/
    # POST: Triggers a full PASTA methodology assessment and returns a generated PDF report.
    # GET: Retrieves the saved PASTA assessment data as JSON.
    path("pasta-assess/<int:pk>/", views.PastaAssessmentView.as_view(), name="pasta-assess-model"),

    # GET: Retrieves an existing attack tree in Mermaid diagram format.
    # POST: Generates a new attack tree if one does not exist.
    path("attack-tree/<int:pk>/", views.AttackTreeView.as_view(), name="attack-tree-view"),
    
    # GET /report/<int:pk>/?format=<csv|json|markdown>
    # Downloads the main STRIDE threat model report in a specified format (defaults to CSV).
    path("report/<int:pk>/", views.ReportView.as_view(), name="get-report"),
    
    # GET /status/<int:pk>/
    # Checks the background processing status (e.g., Pending, Processing, Completed, Failed)
    # of the document ingestion for a specific assessment.
    path("status/<int:pk>/", views.StatusView.as_view(), name="check-status"),

    # GET /dread-report/<int:pk>/
    # Retrieves the full JSON data of a completed DREAD assessment report.
    path("dread-report/<int:pk>/", views.DreadReportView.as_view(), name="dread-report"),

    # GET: Exports the existing attack tree as a downloadable PDF file.
    path("attack-tree/<int:pk>/export/", views.AttackTreeExportView.as_view(), name="attack-tree-export"),

    # GET /pasta-assess/<int:pk>/export/
    # Downloads a PDF report of the EXISTING PASTA data.
    path("pasta-assess/<int:pk>/export/", views.PastaExportView.as_view(), name="pasta-export"),
    
    # GET /dread-status/<int:pk>/
    # Checks the completion status ('Completed' or 'Not Started') of the DREAD assessment.
    path("dread-status/<int:pk>/", views.DreadStatusView.as_view(), name="dread-status"),

    # GET /pasta-status/<int:pk>/
    # Checks the completion status ('Completed' or 'Not Started') of the PASTA assessment.
    path("pasta-status/<int:pk>/", views.PastaStatusView.as_view(), name="pasta-status"),

    # GET /attack-tree-status/<int:pk>/
    # Checks if an Attack Tree has been generated ('Completed') or not ('Not Started').
    path("attack-tree-status/<int:pk>/", views.AttackTreeStatusView.as_view(), name="attack-tree-status"),
    
    # GET /analysis-status/<int:pk>/
    # Checks the completion status of the core STRIDE analysis, distinct from document processing.
    path("analysis-status/<int:pk>/", views.AnalysisStatusView.as_view(), name="analysis-status"),

    # GET /history/
    # Retrieves a log of all actions (e.g., creating assessments, running analyses) 
    # performed by the currently authenticated user, ordered from newest to oldest.
    path("history/", views.HistoryListView.as_view(), name="user-history"),
]