from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class TresViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]  # Requires JWT authentication

    def list(self, request):
        return Response({"message": "Welcome to the AI Attack Lab!"})  # JSON response

class LLMToolViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]  

    def list(self, request):
        return Response({"message": "Welcome to the LLM Attack Suite!"})