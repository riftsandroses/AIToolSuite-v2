from django.db import models
from api_orch.models import PostmanAPI


class SSRFCandidate(models.Model):
    """
    Represents a potential SSRF vulnerability identified by heuristic analysis.
    """
    api = models.ForeignKey(PostmanAPI, on_delete=models.CASCADE, related_name='ssrf_candidates')
    risk_score = models.IntegerField(default=0)
    risk_factors = models.JSONField(default=list, help_text="List of strings explaining why it's a candidate")
    # Store vulnerable components, similar to how it's structured in SSRFDataExtractor output
    vulnerable_components = models.JSONField(default=dict, help_text="Details of vulnerable parameters/headers found")
    identified_at = models.DateTimeField(auto_now_add=True)
    analysis_run_id = models.CharField(max_length=100, blank=True, null=True, help_text="Unique ID for analysis run")
    heuristic_completed_at = models.DateTimeField(blank=True, null=True, help_text="When heuristic analysis completed")

    class Meta:
        ordering = ['-risk_score', 'identified_at']
        verbose_name = "SSRF Candidate"
        verbose_name_plural = "SSRF Candidates"

    def __str__(self):
        return f"SSRF Candidate for {self.api.name} (Score: {self.risk_score})"

class LLMAnalysisResult(models.Model):
    ssrf_candidate = models.ForeignKey(SSRFCandidate, on_delete=models.CASCADE, related_name='analysis_results')
    provider = models.CharField(max_length=100)
    model_used = models.CharField(max_length=100)
    prompt_sent = models.TextField()
    raw_llm_response = models.TextField()
    analysis_timestamp = models.DateTimeField(auto_now_add=True)

    # --- New fields to store structured data ---
    is_ssrf_candidate = models.BooleanField(default=False)
    primary_payload_category = models.CharField(max_length=50, blank=True, null=True)
    vector_category = models.CharField(max_length=50, blank=True, null=True)
    recommended_payload = models.JSONField(blank=True, null=True)
    analysis_run_id = models.CharField(max_length=100, blank=True, null=True, help_text="Links to same analysis run")
    batch_number = models.IntegerField(blank=True, null=True, help_text="Which batch this was processed in")
    
    # --- Deprecated/Backup fields ---
    # We keep parsed_analysis to store the raw JSON, but the primary fields above are now used.
    parsed_analysis = models.JSONField(blank=True, null=True) 
    
    # These can now be derived from is_ssrf_candidate or removed if no longer needed.
    overall_risk = models.CharField(max_length=50, blank=True, null=True) 
    critical_findings_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Analysis for {self.ssrf_candidate.api.name} by {self.model_used}"

class SSRFProof(models.Model):
    """
    Records a successful SSRF exploitation during dynamic testing.
    """
    ssrf_candidate = models.ForeignKey(SSRFCandidate, on_delete=models.CASCADE, related_name='ssrf_proofs')
    payload_used = models.TextField(help_text="The specific payload that succeeded in exploitation")
    injection_point = models.CharField(max_length=255, help_text="Where the payload was injected (e.g., 'query_param:url', 'header:X-Forwarded-For')")
    target_internal_ip_or_domain = models.CharField(max_length=255, help_text="The internal IP or domain targeted (e.g., '169.254.169.254', 'localhost:80')")
    proof_details = models.JSONField(blank=True, null=True, help_text="Details of the proof (e.g., HTTP status, response content snippet, OOB interaction details)")
    exploitation_timestamp = models.DateTimeField(auto_now_add=True)
    # Add status for proof (e.g., 'confirmed', 'false_positive', 'fixed')
    status = models.CharField(max_length=50, default='confirmed', help_text="Status of the dynamic proof")
    analysis_run_id = models.CharField(max_length=100, blank=True, null=True, help_text="Links to same analysis run")
    

    class Meta:
        ordering = ['-exploitation_timestamp']
        verbose_name = "SSRF Proof"
        verbose_name_plural = "SSRF Proofs"

    def __str__(self):
        return f"SSRF Proof for {self.ssrf_candidate.api.name} against {self.target_internal_ip_or_domain}"
    
class Payload(models.Model):
    PAYLOAD_CATEGORIES = [
        ('cloud_metadata', 'Cloud Metadata'),
        ('headers', 'Headers'),
        ('protocols', 'Protocols'),
        ('waf_bypass', 'WAF Bypass'),
        ('encoded', 'Encoded Payloads'),
        ('dns_rebinding', 'DNS Rebinding'),
        ('local_ips', 'Local IPs'),
        ('parameters', 'Parameter Payloads'),
        ('ports', 'Port Payloads'),
    ]
    category = models.CharField(max_length=50, choices=PAYLOAD_CATEGORIES)
    payload = models.CharField(max_length=512)
    description = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.category}: {self.payload}"