# scanner/management/commands/watch_hitlogs.py
import time
import os
from django.core.management.base import BaseCommand
from watchdog.observers import Observer
from django.conf import settings
from scanner.services import HitlogHandler

class Command(BaseCommand):
    help = 'Watch for hitlog.jsonl files and update the database'

    def handle(self, *args, **options):
        # Path to watch (where the yaml and hitlog files are stored)
        path = os.path.join(settings.MEDIA_ROOT, "yaml")
        
        self.stdout.write(self.style.SUCCESS(f'Starting watchdog on {path}'))
        
        event_handler = HitlogHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()