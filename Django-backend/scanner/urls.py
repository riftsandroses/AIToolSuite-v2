from django.urls import path
from .views import ScanAPIView

urlpatterns = [
    path('', ScanAPIView.as_view(), name='llm-scanner-api'),
]
