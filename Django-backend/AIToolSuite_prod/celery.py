# celery.py
from __future__ import absolute_import, unicode_literals
from django.conf import settings
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'AIToolSuite_prod.settings')

app = Celery('AIToolSuite_prod')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'cleanup-old-scans': {
        'task': 'api_4.tasks.cleanup_old_scans_task',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
}
app.conf.timezone = 'UTC'


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
