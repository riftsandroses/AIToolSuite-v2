# tasks.py
from celery import shared_task
import logging
from .docker_service import DockerService
from .models import UserContainer
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
docker_service = DockerService()

@shared_task
def cleanup_expired_containers():
    """
    Task to clean up containers older than 24 hours
    To be scheduled using Celery Beat
    """
    try:
        # Get containers older than 24 hours
        cutoff_time = datetime.now() - timedelta(hours=24)
        expired_containers = UserContainer.objects.filter(
            created_at__lt=cutoff_time,
            is_active=True
        )
        
        count = 0
        for container in expired_containers:
            try:
                # Remove from Docker
                docker_service.remove_container(container.container_id)
                
                # Update database
                container.is_active = False
                container.save()
                
                count += 1
            except Exception as e:
                logger.error(f"Error removing container {container.container_id}: {str(e)}")
        
        logger.info(f"Cleaned up {count} expired containers")
        return count
    except Exception as e:
        logger.error(f"Error in cleanup task: {str(e)}")
        raise