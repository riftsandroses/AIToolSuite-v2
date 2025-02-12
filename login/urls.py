from django.urls import path
from .views import UserLoginView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('', UserLoginView.as_view(), name='api_login'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
