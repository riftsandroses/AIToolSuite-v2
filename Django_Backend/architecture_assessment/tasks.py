"""
tasks.py  —  Celery tasks for architecture_assessment

Register the beat schedule in your Django settings:

    CELERY_BEAT_SCHEDULE = {
        'weekly-security-training': {
            'task': 'architecture_assessment.tasks.run_weekly_training',
            'schedule': crontab(hour=2, minute=0, day_of_week=1),  # Every Monday 02:00
        },
    }

Or use django-celery-beat and create the PeriodicTask via the admin.
"""

from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=2, default_retry_delay=300)
def run_weekly_training(self):
    """
    Distil all unincorporated VulnerabilityFeedback into a refined system-prompt
    addendum and persist it as a completed TrainingJob.

    This task is scheduled to run once a week (Monday 02:00 UTC by default).
    It can also be triggered manually via:
        POST /api/training/
    or via the Celery CLI:
        celery -A <project> call architecture_assessment.tasks.run_weekly_training
    """
    from .services import FeedbackTrainer
    from .models import VulnerabilityFeedback

    pending = VulnerabilityFeedback.objects.filter(incorporated_in_training=False).count()
    if pending == 0:
        logger.info("[training] No unincorporated feedback — skipping training run.")
        return {"status": "skipped", "reason": "no_feedback"}

    logger.info(f"[training] Starting weekly training run with {pending} feedback items.")
    try:
        trainer = FeedbackTrainer()
        job = trainer.run_weekly_training()
        logger.info(
            f"[training] Completed. Job ID={job.id}, "
            f"feedback={job.feedback_count}, "
            f"fp={job.false_positive_count}, "
            f"pc={job.prior_control_count}, "
            f"mf={job.missed_finding_count}"
        )
        return {"status": "completed", "job_id": str(job.id)}
    except Exception as exc:
        logger.exception(f"[training] Training run failed: {exc}")
        raise self.retry(exc=exc)