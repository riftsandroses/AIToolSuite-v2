from django.urls import path
from .views import UserLoginView, TOTPVerifyView, TOTPSetupView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('', UserLoginView.as_view(), name='api_login'),
    path('totp/verify/', TOTPVerifyView.as_view(), name='totp_verify'),
    path('totp/setup/', TOTPSetupView.as_view(), name='totp_setup'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]