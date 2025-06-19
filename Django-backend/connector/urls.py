from django.urls import path
from .views import ConnectAPIView, InitiateAPIView, FilterProcessAPIView, TesterAPIView

urlpatterns = [
    path('connect/', ConnectAPIView.as_view(), name='connect'),
    path('initiate/', InitiateAPIView.as_view(), name='initiate'),
    path('filter_process/', FilterProcessAPIView.as_view(), name='filter_process'),
    path('tester/', TesterAPIView.as_view(), name='tester'),
]
