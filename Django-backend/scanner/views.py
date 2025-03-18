import os
import yaml
import uuid
import subprocess
import re
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import OpenAIDB, AzureDB
from .serializers import OpenAIScanSerializer, AzureScanSerializer

# Mapping of attack categories to probe_spec values
ATTACK_MAPPING = {
    "robustness_evaluation": "continuation.ContinueSlursReclaimedSlursMini,divergence.Repeat,encoding.InjectAscii85,encoding.InjectBase16,encoding.InjectBase2048,encoding.InjectBase32,encoding.InjectBase64,encoding.InjectBraille,encoding.InjectEcoji,encoding.InjectHex,encoding.InjectMorse,encoding.InjectNato,encoding.InjectROT13,encoding.InjectUU,encoding.InjectZalgo,glitch.Glitch100",
    "adversarial_resilience": "av_spam_scanning.EICAR", #,av_spam_scanning.GTUBE,av_spam_scanning.GTphish, fileformats.HF_Files,malwaregen.Evasion,malwaregen.Payload,malwaregen.SubFunctions,malwaregen.TopLevel,xss.MarkdownImageExfil",
    "exploitation_resistance": "dan.AntiDAN,dan.AutoDANCached,dan.ChatGPT_Developer_Mode_RANTI,dan.ChatGPT_Developer_Mode_v2,dan.ChatGPT_Image_Markdown,dan.DAN_Jailbreak,dan.DUDE,dan.DanInTheWildMini,dan.Dan_10_0,dan.Dan_11_0,dan.Dan_6_0,dan.Dan_6_2,dan.Dan_7_0,dan.Dan_8_0,dan.Dan_9_0,donotanswer.DiscriminationExclusionToxicityHatefulOffensive,donotanswer.HumanChatbox,donotanswer.InformationHazard,donotanswer.MaliciousUses,donotanswer.MisinformationHarms,latentinjection.LatentInjectionFactSnippetEiffel,latentinjection.LatentInjectionFactSnippetLegal,latentinjection.LatentInjectionReport,latentinjection.LatentInjectionResume,latentinjection.LatentInjectionTranslationEnFr,latentinjection.LatentInjectionTranslationEnZh,latentinjection.LatentJailbreak,latentinjection.LatentJailbreakMini,latentinjection.LatentWhois,latentinjection.LatentWhoisSnippet,promptinject.HijackHateHumansMini,promptinject.HijackKillHumansMini,promptinject.HijackLongPromptMini,suffix.GCGCached",
    "ethical_alignment": "goodside.Davidjl,goodside.Tag,goodside.ThreatenJSON,goodside.WhoIsRiley,grandma.Slurs,grandma.Substances,grandma.Win10,grandma.Win11,lmrc.Anthropomorphisation,lmrc.Bullying,lmrc.Deadnaming,lmrc.Profanity,lmrc.QuackMedicine,lmrc.SexualContent,lmrc.Sexualisation,lmrc.SlurUsage,realtoxicityprompts.RTPBlank,realtoxicityprompts.RTPFlirtation,realtoxicityprompts.RTPIdentity_Attack,realtoxicityprompts.RTPInsult,realtoxicityprompts.RTPProfanity,realtoxicityprompts.RTPSevere_Toxicity,realtoxicityprompts.RTPSexually_Explicit,realtoxicityprompts.RTPThreat,tap.TAPCached",
    "hallucination_rate": "misleading.FalseAssertion50,packagehallucination.JavaScript,packagehallucination.Python,packagehallucination.Ruby,packagehallucination.Rust,snowball.GraphConnectivityMini,snowball.PrimesMini,snowball.SenatorsMini,topic.WordnetControversial",
}

class ScanAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Require authentication

    def generate_yaml_file(self, scan_name, client_name, client_app_name, attack_name):
        unique_id = str(uuid.uuid4())[:8]
        safe_filename = f"{scan_name.replace(' ', '_')}_{client_name.replace(' ', '_')}_{client_app_name.replace(' ', '_')}_{unique_id}.yaml"
        file_path = os.path.join(settings.MEDIA_ROOT, "yaml", safe_filename)

        attack_keys = [name.strip() for name in attack_name.split(",")]
        probe_specs = [ATTACK_MAPPING[key] for key in attack_keys if key in ATTACK_MAPPING]
        probe_spec_str = ",".join(probe_specs)

        yaml_data = {
            'plugins': {
                'probe_spec': probe_spec_str,
                'detector_spec': 'auto',
            },
            'reporting': {
                'report_prefix': safe_filename.replace(".yaml", ""),
                'report_dir': os.path.join(settings.MEDIA_ROOT, "yaml"),
            },
        }

        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "w") as yaml_file:
            yaml.dump(yaml_data, yaml_file, default_flow_style=False)

        return safe_filename, file_path

    def post(self, request, *args, **kwargs):
        generator = request.data.get('generator')
        api_key = request.data.get('api_key')
        azure_api_key = request.data.get('azure_api_key')
        azure_model_name = request.data.get('azure_model_name')
        azure_deployment_name = request.data.get('azure_deployment_name')
        azure_endpoint_url = request.data.get('azure_endpoint_url')

        if generator == 'openai' and not api_key:
            return Response({"error": "Missing OpenAI API key"}, status=status.HTTP_400_BAD_REQUEST)
        
        elif generator == 'azure' and not azure_api_key:
            return Response({"error": "Missing Azure API key"}, status=status.HTTP_400_BAD_REQUEST)

        elif generator == 'openai':
            serializer = OpenAIScanSerializer(data=request.data)

            os.environ["OPENAI_API_KEY"] = api_key

            if serializer.is_valid():
                yaml_filename, yaml_path = self.generate_yaml_file(
                    serializer.validated_data["scan_name"],
                    serializer.validated_data["client_name"],
                    serializer.validated_data["client_app_name"],
                    serializer.validated_data["attack_name"],
                )
                OpenAIDB.objects.create(user=request.user, yaml_file=yaml_filename, **serializer.validated_data)

                # Run the scan asynchronously
                self.run_garak_scan(yaml_path, serializer.validated_data["model_name"], generator)

                return Response({"message": "Scan initiated"}, status=status.HTTP_202_ACCEPTED)

        elif generator == 'azure':
            serializer = AzureScanSerializer(data=request.data)

            os.environ["AZURE_API_KEY"] = azure_api_key
            os.environ["AZURE_ENDPOINT"] = azure_endpoint_url
            os.environ["AZURE_MODEL_NAME"] = azure_model_name

            if serializer.is_valid():
                yaml_filename, yaml_path = self.generate_yaml_file(
                    serializer.validated_data["scan_name"],
                    serializer.validated_data["client_name"],
                    serializer.validated_data["client_app_name"],
                    serializer.validated_data["attack_name"],
                )
                AzureDB.objects.create(user=request.user, yaml_file=yaml_filename, **serializer.validated_data)

                # Run the scan asynchronously
                self.run_garak_scan(yaml_path, serializer.validated_data["azure_deployment_name"], generator)

                return Response({"message": "Azure scan saved successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def run_garak_scan(self, yaml_path, model_name, generator):
        """
        Run Garak asynchronously as a background process.
        """
        command = ["garak", "--model_type", generator, "--model_name", model_name, "--config", yaml_path]

        subprocess.Popen(command)  # Run in the background
