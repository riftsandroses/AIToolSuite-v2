# signals.py
from django.db.models.signals import post_delete
from django.dispatch import receiver
from .models import UserContainer
from .docker_service import DockerService

docker_service = DockerService()

@receiver(post_delete, sender=UserContainer)
def cleanup_container_on_delete(sender, instance, **kwargs):
    """Remove Docker container when UserContainer record is deleted"""
    try:
        docker_service.remove_container(instance.container_id)
    except Exception as e:
        # Log the error but don't raise - we don't want to break the delete operation
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error removing container {instance.container_id}: {str(e)}")