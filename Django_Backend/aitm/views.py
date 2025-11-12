# views.py
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from django.utils import timezone
import logging
from .models import UserContainer
from .serializers import UserContainerSerializer
from .docker_service import DockerService

logger = logging.getLogger(__name__)

# FIXED: Create DockerService with database service integration
class DatabaseService:
    """Database service to handle UserContainer operations"""
    
    def save_container_details(self, container_details):
        """Save container details to database"""
        try:
            user_id = container_details['user_id']
            
            # Deactivate any existing containers for this user
            UserContainer.objects.filter(
                user_id=user_id, 
                is_active=True
            ).update(is_active=False)
            
            # Create new container record
            user_container = UserContainer.objects.create(
                user_id=user_id,
                container_id=container_details['container_id'],
                container_name=container_details['container_name'],
                port=container_details['port'],
                is_active=True,
                last_accessed=timezone.now()
            )
            logger.info(f"Saved container {container_details['container_id']} to database")
            return user_container
            
        except Exception as e:
            logger.error(f"Error saving container to database: {str(e)}")
            raise
    
    def remove_container_details(self, user_id, container_id):
        """Remove container details from database"""
        try:
            UserContainer.objects.filter(
                user_id=user_id,
                container_id=container_id
            ).update(is_active=False)
            logger.info(f"Deactivated container {container_id} in database")
        except Exception as e:
            logger.error(f"Error removing container from database: {str(e)}")
            raise

# Initialize services
db_service = DatabaseService()
docker_service = DockerService(db_service=db_service)

class UserContainerViewSet(viewsets.ModelViewSet):
    serializer_class = UserContainerSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserContainer.objects.filter(user=self.request.user, is_active=True)
    
    def list(self, request):
        """Get existing container info or create new one - FIXED to prevent multiple containers"""
        try:
            user_id = request.user.id
            
            # FIXED: Use the new get_or_create_container method to prevent duplicates
            container_info = docker_service.get_or_create_container(user_id)
            
            # Get or create database record
            user_container, created = UserContainer.objects.get_or_create(
                user=request.user,
                container_id=container_info['container_id'],
                defaults={
                    'container_name': container_info['container_name'],
                    'port': container_info['port'],
                    'is_active': True,
                    'last_accessed': timezone.now()
                }
            )
            
            if not created:
                # Update last accessed time
                user_container.last_accessed = timezone.now()
                user_container.is_active = True
                user_container.save()
            
            # FIXED: Return container_url in the response
            response_data = UserContainerSerializer(user_container).data
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Error in container list endpoint: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='get-or-create')
    def get_or_create(self, request):
        """
        FIXED: Dedicated endpoint for get-or-create that matches frontend expectations
        This prevents the infinite loop issue in the React component
        """
        try:
            user_id = request.user.id
            
            # Use the Docker service method that handles container reuse
            container_info = docker_service.get_or_create_container(user_id)
            
            # Ensure database record exists and is up to date
            user_container, created = UserContainer.objects.get_or_create(
                user=request.user,
                container_id=container_info['container_id'],
                defaults={
                    'container_name': container_info['container_name'],
                    'port': container_info['port'],
                    'is_active': True,
                    'last_accessed': timezone.now()
                }
            )
            
            if not created:
                user_container.last_accessed = timezone.now()
                user_container.is_active = True
                user_container.save()
            
            # Return response in format expected by frontend
            return Response({
                'success': True,
                'container_url': f"https://user{user_id}.dev.aitoolsuite.xyz",
                'subdomain': f"user{user_id}.dev.aitoolsuite.xyz",
                'container_id': container_info['container_id'],
                'status': container_info['status'],
                'port': container_info['port']
            })
            
        except Exception as e:
            logger.error(f"Error in get_or_create endpoint: {str(e)}")
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'])
    def cleanup(self, request):
        """Clean up expired containers"""
        try:
            hours = request.data.get('hours', 168)  # Default 7 days
            removed_count = docker_service.cleanup_expired_containers(hours)
            
            # Also clean up database records
            UserContainer.objects.filter(
                created_at__lt=timezone.now() - timezone.timedelta(hours=hours),
                is_active=True
            ).update(is_active=False)
            
            return Response({
                'success': True,
                'removed_count': removed_count
            })
        except Exception as e:
            logger.error(f"Error in cleanup endpoint: {str(e)}")
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def destroy(self, request, pk=None):
        """Remove a specific container"""
        try:
            user_container = self.get_object()
            
            # Remove Docker container
            docker_service.remove_container(
                user_container.container_id, 
                user_container.user.id
            )
            
            # Deactivate database record
            user_container.is_active = False
            user_container.save()
            
            return Response({'success': True})
        except Exception as e:
            logger.error(f"Error removing container: {str(e)}")
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)