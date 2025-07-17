from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserTOTP

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

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