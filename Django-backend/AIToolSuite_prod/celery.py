# celery.py (in your project directory)
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'AIToolSuite_prod.settings')

app = Celery('AIToolSuite_prod')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs
app.autodiscover_tasks()

# Configure periodic tasks
app.conf.beat_schedule = {
    'cleanup-expired-containers': {
        'task': 'aitm.tasks.cleanup_expired_containers',
        'schedule': 3600.0,  # Run every hour
    },
}