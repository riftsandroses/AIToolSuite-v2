from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from .serializers import (
    LoginSerializer, 
    TOTPVerifySerializer, 
    TOTPSetupSerializer,
    LoginResponseSerializer,
    SuccessLoginSerializer
)
from .models import UserTOTP
import jwt
import datetime


# ---------------------------------------------------------------------------
# Helper: pre-auth token
# ---------------------------------------------------------------------------
# A short-lived, signed token issued ONLY after password is verified.
# TOTP endpoints require this token so they cannot be reached by simply
# manipulating an error response on the client side.

PRE_AUTH_TOKEN_EXPIRY_SECONDS = 300  # 5 minutes


def _issue_pre_auth_token(user_id: int) -> str:
    """Return a signed JWT that proves the password step was passed."""
    payload = {
        "pre_auth_uid": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=PRE_AUTH_TOKEN_EXPIRY_SECONDS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def _validate_pre_auth_token(token: str) -> int | None:
    """
    Decode and validate the pre-auth token.
    Returns the user_id on success, or None if invalid/expired.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload.get("pre_auth_uid")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

        # Password is correct — issue a short-lived pre-auth token.
        # This token is required by the TOTP endpoints, so they cannot be
        # reached without first passing the password check on the server.
        pre_auth_token = _issue_pre_auth_token(user.id)

        totp_instance, _ = UserTOTP.objects.get_or_create(user=user)

        if totp_instance.is_enabled:
            return Response({
                "requires_totp": True,
                "totp_enabled": True,
                "pre_auth_token": pre_auth_token,
                "message": "Please enter your 6-digit TOTP code",
                "email": email
            }, status=status.HTTP_200_OK)
        else:
            qr_code = totp_instance.get_qr_code()
            return Response({
                "requires_totp": True,
                "totp_enabled": False,
                "pre_auth_token": pre_auth_token,
                "qr_code": qr_code,
                "message": "TOTP is required. Please scan the QR code with your authenticator app and enter the 6-digit code",
                "email": email
            }, status=status.HTTP_200_OK)


class TOTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        # --- Require a valid pre-auth token ---
        pre_auth_token = request.data.get("pre_auth_token")
        if not pre_auth_token:
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        user_id = _validate_pre_auth_token(pre_auth_token)
        if user_id is None:
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        totp_token = serializer.validated_data['totp_token']

        try:
            user = User.objects.get(email=email, id=user_id)   # id must match token
            totp_instance = UserTOTP.objects.get(user=user)
        except (User.DoesNotExist, UserTOTP.DoesNotExist):
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        if totp_instance.is_enabled and totp_instance.verify_token(totp_token):
            refresh = RefreshToken.for_user(user)
            return Response({
                "name": user.first_name + " " + user.last_name,
                "email": user.email,
                "username": user.username,
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid TOTP code"}, status=status.HTTP_400_BAD_REQUEST)


class TOTPSetupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TOTPSetupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        # --- Require a valid pre-auth token ---
        pre_auth_token = request.data.get("pre_auth_token")
        if not pre_auth_token:
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        user_id = _validate_pre_auth_token(pre_auth_token)
        if user_id is None:
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        totp_token = serializer.validated_data['totp_token']

        try:
            user = User.objects.get(email=email, id=user_id)   # id must match token
            totp_instance = UserTOTP.objects.get(user=user)
        except (User.DoesNotExist, UserTOTP.DoesNotExist):
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

        if not totp_instance.is_enabled and totp_instance.verify_token(totp_token):
            totp_instance.is_enabled = True
            totp_instance.save()

            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "TOTP setup successful",
                "email": user.email,
                "username": user.username,
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid TOTP code"}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            RefreshToken(refresh_token).blacklist()
            return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
        except TokenError:
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST
            )