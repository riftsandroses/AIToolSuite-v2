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
    TaskStatusViewTC1
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
]