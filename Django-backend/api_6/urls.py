# urls.py
from django.urls import path, include
from . import views

app_name = 'api_6'

urlpatterns = [
    # TC-1 Mass Account Creation
    path('scans-tc1/start/', views.VulnerabilityScanStartTC1.as_view(), name='scan-start'),
    path('scans-tc1/<int:scan_id>/status/', views.VulnerabilityScanStatusTC1.as_view(), name='scan-status'),
    path('scans-tc1/<int:scan_id>/stop/', views.VulnerabilityScanStopTC1.as_view(), name='scan-stop'),
    path('scans-tc1/<int:scan_id>/stats/', views.ScanStatsTC1.as_view(), name='scan-stats'),
    path('scans-tc1/<int:scan_id>/export/', views.VulnerabilityExportTC1.as_view(), name='scan-export'),
    path('scans-tc1/<int:scan_id>/report/', views.ScanReportsTC1.as_view(), name='scan-report'),
    path('scans-tc1/', views.ScanListTC1.as_view(), name='scan-list'),
    path('results-tc1/', views.ScanResultsFilteredTC1.as_view(), name='results-filtered'),
    path('results-tc1/<uuid:test_id>/', views.VulnerabilityTestDetailTC1.as_view(), name='test-detail'),
    path('summary-tc1/', views.VulnerabilitySummaryTC1.as_view(), name='vulnerability-summary'),
    path('history-tc1/', views.ScanHistoryTC1.as_view(), name='scan-history'),
]