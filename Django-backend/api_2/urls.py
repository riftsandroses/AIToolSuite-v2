from django.urls import path
from .views import (
    ScanInitiateViewTC1,
    ScanResultsViewTC1,
    ScanStatusViewTC1,
    ScanStatsViewTC1,
    ScanHistoryViewTC1,
    VulnerabilitySummaryViewTC1,
    ScanResultDetailViewTC1,
    ScanCancelViewTC1,
    DashboardViewTC1,
    TaskStatusViewTC1,
    ScanInitiateTC2View,
    ScanResultsTC2View,
    ScanStatusTC2View,
    ScanStatsTC2View,
    ScanHistoryTC2View,
    VulnerabilitySummaryTC2View,
    ScanSummaryTC2View,
    TestCredentialsTC2View,
    ScanCancelTC2View,
    ScanResultDetailTC2View,
)

app_name = 'api_2'

urlpatterns = [
    # TC-1 Missing/Weak Authentication on Sensitive Endpoints
    path('scan-tc1/initiate/', ScanInitiateViewTC1.as_view(), name='scan_initiate'),
    path('scan-tc1/<int:scan_id>/status/', ScanStatusViewTC1.as_view(), name='scan_status'),
    path('scan-tc1/<int:scan_id>/cancel/', ScanCancelViewTC1.as_view(), name='scan_cancel'),
    path('results-tc1/', ScanResultsViewTC1.as_view(), name='scan_results'),
    path('results-tc1/<int:result_id>/', ScanResultDetailViewTC1.as_view(), name='scan_result_detail'),
    path('vulnerability-summary-tc1/', VulnerabilitySummaryViewTC1.as_view(), name='vulnerability_summary_all'),
    path('vulnerability-summary-tc1/<int:scan_id>/', VulnerabilitySummaryViewTC1.as_view(), name='vulnerability_summary'),
    path('stats-tc1/', ScanStatsViewTC1.as_view(), name='scan_stats'),
    path('history-tc1/', ScanHistoryViewTC1.as_view(), name='scan_history'),
    path('dashboard-tc1/', DashboardViewTC1.as_view(), name='dashboard'),
    path('task-tc1/<str:task_id>/status/', TaskStatusViewTC1.as_view(), name='task_status'),

    # TC-2 Unrestricted Credential Stuffing
    path('scan-tc2/initiate/', ScanInitiateTC2View.as_view(), name='scan-initiate-tc2'),
    path('scan-tc2/<int:scan_id>/status/', ScanStatusTC2View.as_view(), name='scan-status-tc2'),
    path('scan-tc2/<int:scan_id>/cancel/', ScanCancelTC2View.as_view(), name='scan-cancel-tc2'),
    path('scan-tc2/<int:scan_id>/summary/', ScanSummaryTC2View.as_view(), name='scan-summary-detail-tc2'),
    path('scan-tc2/<int:scan_id>/vulnerability-summary/', VulnerabilitySummaryTC2View.as_view(), name='vulnerability-summary-tc2'),
    path('results-tc2/', ScanResultsTC2View.as_view(), name='scan-results-tc2'),
    path('results-tc2/<int:result_id>/', ScanResultDetailTC2View.as_view(), name='scan-result-detail-tc2'),
    path('summaries-tc2/', ScanSummaryTC2View.as_view(), name='scan-summaries-tc2'),
    path('stats-tc2/', ScanStatsTC2View.as_view(), name='scan-stats-tc2'),
    path('history-tc2/', ScanHistoryTC2View.as_view(), name='scan-history-tc2'),
    path('credentials-tc2/', TestCredentialsTC2View.as_view(), name='test-credentials-tc2'),
]