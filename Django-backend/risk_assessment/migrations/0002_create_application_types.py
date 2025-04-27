from django.db import migrations

def create_application_types(apps, schema_editor):
    ApplicationType = apps.get_model('risk_assessment', 'ApplicationType')
    
    # Create application types
    types = [
        'ChatBot & Virtual Assistant Type Application',
        'Search & Knowledge Management Type Application',
        'Data Analytics & Business Intelligence Type Application',
        'Coding & Software Development Type Application',
        'Content Generation & Marketing Type Application',
        'Education & E-learning Type Application',
        'Cyber Defence & Detection Type Application',
        'Legal & Compliance Type Application',
        'Healthcare & Medical related Application',
        'Finance & Investment Type Application',
        'Asset Monitoring Application'
    ]
    
    for app_type in types:
        ApplicationType.objects.create(name=app_type)

def delete_application_types(apps, schema_editor):
    ApplicationType = apps.get_model('risk_assessment', 'ApplicationType')
    ApplicationType.objects.all().delete()

class Migration(migrations.Migration):
    dependencies = [
        ('risk_assessment', '0001_initial'),  # Change this to your initial migration
    ]

    operations = [
        migrations.RunPython(create_application_types, delete_application_types),
    ]