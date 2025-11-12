# threat_model/tasks.py
from celery import shared_task
from .models import Document, ThreatModel
from .methodologies.ThreatModel import generate_correlation_report
from django.conf import settings
from .processing.processing_controller import process_uploaded_documents # <-- Import your main processing function
import logging

logger = logging.getLogger(__name__)

@shared_task
def process_threat_model_documents(threat_model_id):
    """
    Celery task to process all uploaded documents for a given threat model.
    """
    try:
        threat_model = ThreatModel.objects.get(id=threat_model_id)
        
        logger.info(f"Starting processing for all documents in Threat Model {threat_model.id} for app: {threat_model.app_name}...")
        threat_model.status = ThreatModel.StatusChoices.PROCESSING
        threat_model.save()
        # Calling main processing function with the application name
        process_uploaded_documents(threat_model.app_name, threat_model_id=threat_model.id)

        
        # Once processing is complete, update the status
        threat_model.status = ThreatModel.StatusChoices.COMPLETED
        threat_model.save()
        
        logger.info(f"Successfully processed all documents for Threat Model {threat_model.id}")
        return threat_model.id

    except ThreatModel.DoesNotExist:
        logger.error(f"ThreatModel with ID {threat_model_id} not found.")
        return f"Error: ThreatModel with ID {threat_model_id} not found."
    except Exception as e:
        logger.error(f"An error occurred during processing of Threat Model {threat_model_id}: {e}")
        
        try:
            threat_model = ThreatModel.objects.get(id=threat_model_id)
            threat_model.status = ThreatModel.StatusChoices.FAILED
            threat_model.save()
        except ThreatModel.DoesNotExist:
            pass

        return f"Error processing Threat Model {threat_model_id}"
    
@shared_task
def correlate_threat_model(previous_task_result):
    """
    Celery task to generate a correlation report after processing is complete.
    It receives the threat_model_id from the previous task in the chain.
    """
    threat_model_id = previous_task_result
    try:
        logger.info(f"Starting correlation for Threat Model {threat_model_id}...")
        api_key = settings.OPENAI_API_KEY
        if not api_key:
            logger.error("OPENAI_API_KEY not configured for correlation task.")
            return f"Error: API Key not configured."

        generate_correlation_report(
            threat_model_id=threat_model_id,
            api_key=api_key,
            model_name="gpt-4.1" # Or use a setting
        )
        logger.info(f"Successfully generated correlation report for Threat Model {threat_model_id}")
        return f"Correlation complete for Threat Model {threat_model_id}"
    except Exception as e:
        logger.error(f"An error occurred during correlation of Threat Model {threat_model_id}: {e}")
        return f"Error correlating Threat Model {threat_model_id}"