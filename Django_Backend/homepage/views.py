from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class HomepageView(APIView):
    permission_classes = [IsAuthenticated]  # Requires JWT authentication

    def get(self, request):
        return Response({"message": "Welcome to the homepage!"})
