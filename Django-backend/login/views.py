from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from .serializers import (
    LoginSerializer, 
    TOTPVerifySerializer, 
    TOTPSetupSerializer,
    LoginResponseSerializer,
    SuccessLoginSerializer
)
from .models import UserTOTP

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

            if user.check_password(password):
                # Get or create TOTP instance for user
                totp_instance, created = UserTOTP.objects.get_or_create(user=user)
                
                if totp_instance.is_enabled:
                    # User has TOTP enabled, require TOTP verification
                    return Response({
                        "requires_totp": True,
                        "totp_enabled": True,
                        "message": "Please enter your 6-digit TOTP code",
                        "email": email
                    }, status=status.HTTP_200_OK)
                else:
                    # User doesn't have TOTP enabled, show QR code for setup
                    qr_code = totp_instance.get_qr_code()
                    return Response({
                        "requires_totp": True,
                        "totp_enabled": False,
                        "qr_code": qr_code,
                        "message": "TOTP is required. Please scan the QR code with your authenticator app and enter the 6-digit code",
                        "email": email
                    }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

class TOTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            totp_token = serializer.validated_data['totp_token']

            try:
                user = User.objects.get(email=email)
                totp_instance = UserTOTP.objects.get(user=user)
            except (User.DoesNotExist, UserTOTP.DoesNotExist):
                return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

            if totp_instance.is_enabled and totp_instance.verify_token(totp_token):
                # TOTP verification successful, generate JWT tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    "name": user.first_name + " " + user.last_name,
                    "email": user.email,
                    "username": user.username,
                    "access": str(refresh.access_token),
                    "refresh": str(refresh)
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid TOTP code"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

class TOTPSetupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPSetupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            totp_token = serializer.validated_data['totp_token']

            try:
                user = User.objects.get(email=email)
                totp_instance = UserTOTP.objects.get(user=user)
            except (User.DoesNotExist, UserTOTP.DoesNotExist):
                return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

            if not totp_instance.is_enabled and totp_instance.verify_token(totp_token):
                # First time TOTP setup successful
                totp_instance.is_enabled = True
                totp_instance.save()
                
                # Generate JWT tokens after successful setup
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    "message": "TOTP setup successful",
                    "name": user.first_name + " " + user.last_name,
                    "email": user.email,
                    "username": user.username,
                    "access": str(refresh.access_token),
                    "refresh": str(refresh)
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid TOTP code"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)