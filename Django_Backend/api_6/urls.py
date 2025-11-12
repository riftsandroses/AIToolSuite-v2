# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
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

    # TC-2 Product Scalping Exploits

    # TC-3 Coupon/Promotional Code Abuse
    path('health-tc3/', views.HealthCheckTC3View.as_view(), name='health_check'),
    path('scans-tc3/', views.ScanListTC3View.as_view(), name='scan_list'),
    path('scans-tc3/create/', views.ScanCreateTC3View.as_view(), name='scan_create'),
    path('scans-tc3/<uuid:scan_id>/', views.ScanDetailTC3View.as_view(), name='scan_detail'),
    path('scans-tc3/<uuid:scan_id>/status/', views.ScanStatusTC3View.as_view(), name='scan_status'),
    path('scans-tc3/<uuid:scan_id>/cancel/', views.ScanCancelTC3View.as_view(), name='scan_cancel'),
    path('scans-tc3/<uuid:scan_id>/report/', views.ScanReportTC3View.as_view(), name='scan_report'),
    path('scans-tc3/<uuid:scan_id>/results/', views.ScanResultsTC3View.as_view(), name='scan_results'),
    path('scans/<uuid:scan_id>/vulnerabilities/summary/', views.VulnerabilitySummaryTC3View.as_view(), name='vulnerability_summary'),
    path('vulnerabilities-tc3/', views.VulnerabilityListTC3View.as_view(), name='vulnerability_list'),
    path('vulnerabilities-tc3/<uuid:vulnerability_id>/', views.VulnerabilityDetailTC3View.as_view(), name='vulnerability_detail'),
    path('stats-tc3/', views.ScanStatsTC3View.as_view(), name='scan_stats'),
    path('history-tc3/', views.ScanHistoryTC3View.as_view(), name='scan_history'),
    path('test-cases-tc3/', views.CouponTestCaseTC3View.as_view(), name='test_cases'),
]