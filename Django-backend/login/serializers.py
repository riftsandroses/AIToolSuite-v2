from rest_framework import serializers
from django.contrib.auth.models import User
from django.conf import settings
import requests
from .models import UserTOTP

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    hcaptcha_response = serializers.CharField(write_only=True)

    def validate_hcaptcha_response(self, value):
        """Validate hCaptcha response"""
        if not value:
            raise serializers.ValidationError("hCaptcha response is required")
        
        # Make request to hCaptcha API
        data = {
            'secret': settings.HCAPTCHA_SECRET_KEY,
            'response': value,
            'remoteip': self.context.get('request').META.get('REMOTE_ADDR', '')
        }
        
        try:
            response = requests.post('https://hcaptcha.com/siteverify', data=data, timeout=10)
            result = response.json()
            
            if not result.get('success', False):
                raise serializers.ValidationError("Invalid hCaptcha. Please try again.")
                
        except requests.RequestException:
            raise serializers.ValidationError("hCaptcha verification failed. Please try again.")
        
        return value

class TOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    totp_token = serializers.CharField(max_length=6, min_length=6)

class TOTPSetupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    totp_token = serializers.CharField(max_length=6, min_length=6)

class LoginResponseSerializer(serializers.Serializer):
    """Serializer for login response when credentials are valid but TOTP is needed"""
    requires_totp = serializers.BooleanField()
    totp_enabled = serializers.BooleanField()
    qr_code = serializers.CharField(required=False)
    message = serializers.CharField()
    email = serializers.EmailField()

class SuccessLoginSerializer(serializers.Serializer):
    """Serializer for successful login with tokens"""
    name = serializers.CharField()
    email = serializers.EmailField()
    username = serializers.CharField()
    access = serializers.CharField()
    refresh = serializers.CharField()