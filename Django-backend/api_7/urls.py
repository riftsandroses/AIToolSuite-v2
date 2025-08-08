from django.urls import path
from .views import SSRFCompleteAnalysisView, SSRFAnalysisHistoryView

app_name = 'api_7'

urlpatterns = [
    path('scans/<int:scan_id>/ssrf-analysis/', SSRFCompleteAnalysisView.as_view(), name='complete-ssrf-analysis'),
    path('ssrf/bulk-analysis/', SSRFCompleteAnalysisView.as_view(), name='bulk-ssrf-analysis'),
    path('scans/<int:scan_id>/ssrf-history/', SSRFAnalysisHistoryView.as_view(), name='scan-ssrf-history'),
    path('candidates/<int:candidate_id>/history/', SSRFAnalysisHistoryView.as_view(), name='candidate-history'),
    path('ssrf/history/', SSRFAnalysisHistoryView.as_view(), name='user-ssrf-history'),
]

"""
🚀 PRIMARY WORKFLOW - ONE API DOES EVERYTHING WITH AUTO-CONTINUATION:

1. SINGLE SCAN COMPLETE ANALYSIS WITH AUTO-CONTINUATION:
   POST /scans/{scan_id}/ssrf-analysis/
   {
     "min_risk_score": 10,             // Lower threshold = more comprehensive
     "max_candidates_per_batch": 30,   // Process 30 candidates per batch  
     "max_total_candidates": 150,      // Safety limit (5 batches max)
     "llm_batch_size": 5,              // 5 candidates per LLM call within each batch
     "auto_continue": true,            // Automatically process ALL qualified candidates
     "llm_provider": "openai",
     "skip_dynamic_analysis": false,
     "reanalyze": false
   }
   
   ✅ FULL AUTOMATION - What happens:
      → Heuristic finds ALL candidates with score ≥ 10 (could be 95 candidates)
      → Automatically splits into batches: 
        * Batch 1: Candidates 1-30 (highest risk)
        * Batch 2: Candidates 31-60  
        * Batch 3: Candidates 61-90
        * Batch 4: Candidates 91-95 (remaining)
      → Each batch: LLM analysis (5 at a time) → Dynamic testing
      → Returns complete results from ALL batches

2. MULTI-SCAN BULK ANALYSIS WITH AUTO-CONTINUATION:
   POST /ssrf/bulk-analysis/
   {
     "scan_ids": [1, 2, 3, 4],
     "min_risk_score": 10,
     "max_candidates_per_scan": 30,    // Batch size per scan
     "max_total_per_scan": 150,        // Safety limit per scan  
     "auto_continue": true,            // Process ALL candidates in each scan
     "skip_dynamic_analysis": false
   }

📊 HISTORY & RESULTS VIEWING (unchanged):

1. VIEW SCAN RESULTS:
   GET /scans/{scan_id}/ssrf-history/
   → Complete timeline and results including all batch details

2. VIEW CANDIDATE DETAILS:
   GET /candidates/{candidate_id}/history/
   → Detailed analysis history for specific candidate

3. VIEW USER DASHBOARD:
   GET /ssrf/history/
   → Overview of all SSRF analyses performed by user

🔥 NEW AUTO-CONTINUATION FEATURES:
- ✅ ZERO candidate limits (processes ALL qualified candidates)
- ✅ Intelligent batching (30 candidates per batch)  
- ✅ LLM sub-batching (5 per LLM call within each batch)
- ✅ Automatic progression through ALL batches
- ✅ Complete coverage without user intervention
- ✅ Safety limits prevent runaway processes
- ✅ Detailed batch progress tracking
- ✅ Error resilience (failed batch doesn't stop others)
- ✅ Rate limiting between batches

EXAMPLE REAL-WORLD FLOW:
→ Scan finds 87 candidates with score ≥ 10
→ Auto-batches: [1-30], [31-60], [61-87]  
→ Each batch: LLM → Dynamic → Results
→ Complete analysis of ALL 87 candidates automatically
→ Zero user intervention required
"""