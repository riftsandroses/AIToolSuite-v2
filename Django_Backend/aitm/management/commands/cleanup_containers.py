# management/commands/cleanup_containers.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from ...docker_service import DockerService
from ...models import UserContainer

class Command(BaseCommand):
    help = 'Clean up expired containers and sync database'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=168,  # 1 week
            help='Hours after which containers are considered expired'
        )
    
    def handle(self, *args, **options):
        docker_service = DockerService()
        hours = options['hours']
        
        # Clean up expired containers from Docker
        removed_count = docker_service.cleanup_expired_containers(hours)
        
        # Clean up database records for non-existent containers
        cutoff_time = timezone.now() - timedelta(hours=hours)
        expired_db_records = UserContainer.objects.filter(
            created_at__lt=cutoff_time,
            is_active=True
        )
        
        db_cleanup_count = 0
        for record in expired_db_records:
            # Check if container still exists in Docker
            try:
                container_info = docker_service.get_user_container(record.user.id)
                if not container_info:
                    record.is_active = False
                    record.save()
                    db_cleanup_count += 1
            except:
                record.is_active = False
                record.save()
                db_cleanup_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully cleaned up {removed_count} Docker containers '
                f'and {db_cleanup_count} database records'
            )
        )