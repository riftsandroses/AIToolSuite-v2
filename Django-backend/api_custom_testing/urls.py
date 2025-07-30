from django.urls import path
from .views import SQLInjectionTestView, ChatGPTSQLInjectionTestView, ScanResultsView

urlpatterns = [
    path('api_custom_testing/test-sql-injection/', SQLInjectionTestView.as_view(), name='test_sql_injection'),
    path('api_custom_testing/test-sql-injection-chatgpt/', ChatGPTSQLInjectionTestView.as_view(), name='test_sql_injection_chatgpt'),
    path('api_custom_testing/results/<str:scan_id>/', ScanResultsView.as_view(), name='scan_results'),
]