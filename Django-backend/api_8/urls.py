from django.urls import path
from .views import (
    CORSScanStartTC1View,
    CORSScanResultsTC1View,
    CORSScanStatusTC1View,
    CORSVulnerabilitySummaryTC1View,
    CORSScanStatsTC1View,
    CORSScanHistoryTC1View,
    CORSResultDetailTC1View,
    CORSScanDeleteTC1View,
    CORSScanRetryTC1View
)

urlpatterns = [
    # TC-1 CORS Misconfiguration
    path('cors/scan/start/', CORSScanStartTC1View.as_view(), name='cors_scan_start_tc1'),
    path('cors/scan/results/', CORSScanResultsTC1View.as_view(), name='cors_scan_results_tc1'),
    path('cors/scan/status/', CORSScanStatusTC1View.as_view(), name='cors_scan_status_tc1'),
    path('cors/vulnerability/summary/', CORSVulnerabilitySummaryTC1View.as_view(), name='cors_vulnerability_summary_tc1'),
    path('cors/scan/stats/', CORSScanStatsTC1View.as_view(), name='cors_scan_stats_tc1'),
    path('cors/scan/history/', CORSScanHistoryTC1View.as_view(), name='cors_scan_history_tc1'),
    path('cors/result/<int:result_id>/', CORSResultDetailTC1View.as_view(), name='cors_result_detail_tc1'),
    path('cors/scan/delete/', CORSScanDeleteTC1View.as_view(), name='cors_scan_delete_tc1'),
    path('cors/scan/retry/', CORSScanRetryTC1View.as_view(), name='cors_scan_retry_tc1'),
]