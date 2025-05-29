# views.py
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import UserContainer
from .serializers import UserContainerSerializer
from .docker_service import DockerService

docker_service = DockerService()

class UserContainerViewSet(viewsets.ModelViewSet):
    serializer_class = UserContainerSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserContainer.objects.filter(user=self.request.user)
    
    def list(self, request):
        """Get existing container info or create new one"""
        try:
            # Check if user already has a container
            user_container = UserContainer.objects.filter(user=request.user, is_active=True).first()
            
            if user_container:
                # Verify container still exists in Docker
                container_info = docker_service.get_user_container(request.user.id)
                
                if not container_info:
                    # Container doesn't exist in Docker anymore, create a new one
                    user_container.is_active = False
                    user_container.save()
                    return self._create_new_container(request)
                
                # Update container status and ensure it's running
                if container_info['status'] != 'running':
                    # Start the container if it's not running
                    try:
                        container = docker_service.client.containers.get(container_info['container_id'])
                        container.start()
                    except Exception as e:
                        # If we can't start it, create a new one
                        user_container.is_active = False
                        user_container.save()
                        return self._create_new_container(request)
                
                serializer = self.get_serializer(user_container)
                return Response(serializer.data)
            else:
                # Create new container if user doesn't have one
                return self._create_new_container(request)
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _create_new_container(self, request):
        """Create a new container for the user"""
        try:
            # Create new Docker container
            container_info = docker_service.create_container(request.user.id)
            
            # Save container info to database
            user_container = UserContainer.objects.create(
                user=request.user,
                container_id=container_info['container_id'],
                container_name=container_info['container_name'],
                port=container_info['port']
            )
            
            serializer = self.get_serializer(user_container)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )