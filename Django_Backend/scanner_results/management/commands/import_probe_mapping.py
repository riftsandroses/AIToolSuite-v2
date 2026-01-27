import pandas as pd
from django.core.management.base import BaseCommand
from scanner_results.models import ProbeControlMapping

class Command(BaseCommand):
    help = 'Import probe control mappings from Excel sheet'

    def add_arguments(self, parser):
        parser.add_argument('excel_file', type=str, help='Path to Excel file')

    def handle(self, *args, **options):
        excel_file = options['excel_file']
        
        try:
            # Read data from Excel file
            df = pd.read_excel(excel_file)

            print("RAW COLUMNS:")
            for c in df.columns:
                print(repr(c))
            
            # Clear existing data
            ProbeControlMapping.objects.all().delete()
            
            # Import new data
            for _, row in df.iterrows():
                ProbeControlMapping.objects.create(
                    probe_name=row['Name'],
                    control_title=row['Control Title'],
                    control_category=row['Control Category'],
                    control_description=row['Control Description'],
                    control_observation=row['Control Observation'],
                    control_impact=row['Control Impact'],
                    control_recommendation=row['Control Recommendation'],
                    severity=row['Severity'],
                    owasp_top_10_for_llms=row['OWASP Top 10 for LLMs'],
                    mitre_atlas=row['MITRE ATLAS']
                )
            
            self.stdout.write(self.style.SUCCESS(f'Successfully imported {len(df)} probe mappings'))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error importing data: {str(e)}'))