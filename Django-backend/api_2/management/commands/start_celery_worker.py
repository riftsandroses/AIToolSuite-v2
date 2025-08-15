from django.core.management.base import BaseCommand
import subprocess
import sys

class Command(BaseCommand):
    help = 'Start Celery worker'

    def add_arguments(self, parser):
        parser.add_argument(
            '--loglevel',
            default='info',
            help='Logging level'
        )
        parser.add_argument(
            '--concurrency',
            type=int,
            default=4,
            help='Number of concurrent workers'
        )

    def handle(self, *args, **options):
        cmd = [
            'celery', 
            '-A', 'AIToolSuite_prod',  # Replace with your project name
            'worker',
            '--loglevel=' + options['loglevel'],
            '--concurrency=' + str(options['concurrency'])
        ]
        
        self.stdout.write(f"Starting Celery worker: {' '.join(cmd)}")
        subprocess.call(cmd)