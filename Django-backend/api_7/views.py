import json
import logging
import subprocess
import threading
import time
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.management import call_command
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import transaction
from django.db.models import Q, Count, Max
from django.conf import settings
from api_orch.models import Scan, PostmanAPI
from .security_utils.interactsh_manager import InteractshManager
from .security_utils.dynamic_analyzer import EnhancedSSRFAnalyzer, OutOfBandServer
from .models import SSRFCandidate, LLMAnalysisResult, SSRFProof
from .security_utils.ssrf_detection import SSRFDataExtractor, SSRFLLMDataFormatter
from .security_utils.llm_integrations import analyze_ssrf_with_llm
from .serializers import SSRFCandidateSerializer, LLMAnalysisResultSerializer, SSRFProofSerializer

logger = logging.getLogger(__name__)

class SSRFCompleteAnalysisView(APIView):
    """
    Complete SSRF Analysis Pipeline - Single API for entire workflow.
    
    POST /api/scans/{scan_id}/ssrf-analysis/
    POST /api/ssrf/bulk-analysis/  (for multiple scans)
    
    This API handles the complete SSRF analysis pipeline:
    1. Heuristic Analysis: Identifies and filters candidates
    2. LLM Analysis: Processes candidates in batches (configurable batch size)
    3. Dynamic Analysis: Tests LLM-confirmed vulnerabilities
    4. Returns comprehensive results from all phases
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, scan_id=None):
        if scan_id:
            return self._analyze_single_scan(request, scan_id)
        else:
            return self._analyze_multiple_scans(request)

    def _start_interactsh_server(self, max_retries: int = 2, custom_server: str = None):
        """Start Interactsh server using the improved InteractshManager"""
        logger.info("Attempting to start Interactsh server...")
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Interactsh startup attempt {attempt + 1}/{max_retries}")
                
                interactsh_manager = InteractshManager(custom_server=custom_server)
                
                if interactsh_manager.start_client(max_retries=2):  # Allow 2 internal retries per attempt
                    # Give extra time for domain extraction
                    domain = interactsh_manager.get_domain_url(timeout=25)
                    
                    if domain:
                        logger.info(f"Successfully started Interactsh with domain: {domain}")
                        
                        # Verify the client is still healthy
                        if interactsh_manager.is_healthy():
                            return interactsh_manager, domain
                        else:
                            logger.warning("Interactsh client not healthy after domain extraction")
                            interactsh_manager.stop_client()
                    else:
                        logger.warning(f"Failed to extract domain in attempt {attempt + 1}")
                        interactsh_manager.stop_client()
                else:
                    logger.warning(f"Failed to start interactsh client in attempt {attempt + 1}")
            
            except Exception as e:
                logger.error(f"Exception in interactsh startup attempt {attempt + 1}: {e}")
            
            # Wait before retry (except for last attempt)
            if attempt < max_retries - 1:
                wait_time = 3 * (attempt + 1)  # Progressive backoff
                logger.info(f"Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)
        
        logger.error(f"Failed to start Interactsh after {max_retries} attempts")
        return None, None

    def _verify_interactsh_health(self, interactsh_manager, domain):
        """Verify that Interactsh is still working properly"""
        if not interactsh_manager or not domain:
            return False
            
        try:
            return interactsh_manager.is_healthy()
        except Exception as e:
            logger.error(f"Error checking Interactsh health: {e}")
            return False

    def _stop_interactsh_server(self, interactsh_manager):
        """Safely stop Interactsh server using InteractshManager"""
        if interactsh_manager:
            try:
                interactsh_manager.stop_client()
                logger.info("Successfully stopped Interactsh client")
            except Exception as e:
                logger.error(f"Error stopping Interactsh client: {e}")

    def _analyze_single_scan(self, request, scan_id, user=None):
        """Complete SSRF analysis pipeline for a single scan"""
        if user is None:
            user = request.user

        if not user or not getattr(user, "is_authenticated", False):
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        scan = get_object_or_404(Scan, id=scan_id, created_by=user)

        # Configuration parameters
        interactsh_retries = request.data.get('interactsh_retries', 2)
        custom_interactsh_server = request.data.get('custom_interactsh_server', "oast.pro")
        force_oob_testing = request.data.get('force_oob_testing', False)
        
        # Initialize Interactsh with retry logic
        interactsh_manager, interactsh_url = self._start_interactsh_server(
            max_retries=interactsh_retries,
            custom_server=custom_interactsh_server
        )
        
        # Determine OOB testing capability
        oob_available = interactsh_manager is not None and interactsh_url is not None
        
        if force_oob_testing and not oob_available:
            logger.error("OOB testing was forced but Interactsh is not available")
            return Response({
                "error": "Out-of-band testing was required but Interactsh server could not be started",
                "details": "Set force_oob_testing=false to proceed without OOB testing",
                "interactsh_status": "failed"
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        if not oob_available:
            logger.warning("Interactsh not available - OOB testing will be skipped")

        try:
            scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
            
            # Configuration parameters
            reanalyze = request.data.get('reanalyze', False)
            min_risk_score = request.data.get('min_risk_score', 10)
            max_candidates_per_batch = request.data.get('max_candidates_per_batch', 30)
            max_total_candidates = request.data.get('max_total_candidates', 150)
            llm_batch_size = request.data.get('llm_batch_size', 5)
            llm_provider = request.data.get('llm_provider', 'openai')
            skip_dynamic = request.data.get('skip_dynamic_analysis', False)
            auto_continue = request.data.get('auto_continue', True),
            analysis_run_id = f"run_{scan_id}_{int(time.time())}"

            logger.info(f"Starting complete SSRF analysis for scan {scan_id}")
            
            analysis_results = {
                "scan_info": {
                    "scan_id": scan.id,
                    "scan_name": scan.scan_name,
                    "total_apis": scan.postman_apis.count()
                },
                "pipeline_results": {
                    "heuristic": {},
                    "llm_analysis": {},
                    "dynamic_analysis": {}
                },
                "final_summary": {},
                "interactsh_info": {
                    "startup_attempts": interactsh_retries,
                    "enabled": oob_available,
                    "url": interactsh_url if oob_available else "Not available",
                    "custom_server_used": custom_interactsh_server is not None,
                    "health_status": "healthy" if self._verify_interactsh_health(interactsh_manager, interactsh_url) else "unhealthy"
                }
            }

            # =================================================================
            # PHASE 1: HEURISTIC ANALYSIS & FILTERING
            # =================================================================
            logger.info("📊 Phase 1: Starting heuristic analysis")
            
            with transaction.atomic():
                existing_candidates = SSRFCandidate.objects.filter(api__scan=scan)
                
                if not existing_candidates.exists() or reanalyze:
                    if reanalyze:
                        existing_candidates.delete()
                        logger.info("Cleared existing candidates for reanalysis")
                    
                    # Run heuristic extraction
                    SSRFDataExtractor.extract_ssrf_candidates(scan)
                    all_candidates = SSRFCandidate.objects.filter(api__scan=scan)
                    # UPDATE: Set analysis run ID and completion timestamp
                    all_candidates.update(
                        analysis_run_id=analysis_run_id,
                        heuristic_completed_at=timezone.now()
                    )
                    logger.info(f"Heuristic analysis found {all_candidates.count()} candidates")
                else:
                    all_candidates = existing_candidates
                    logger.info(f"Using existing {all_candidates.count()} candidates")

                # Apply filtering
                filtered_candidates = all_candidates.filter(
                    risk_score__gte=min_risk_score
                ).order_by('-risk_score')
                
                # Apply safety limit
                if filtered_candidates.count() > max_total_candidates:
                    logger.warning(f"Found {filtered_candidates.count()} candidates, limiting to {max_total_candidates} for safety")
                    filtered_candidates = filtered_candidates[:max_total_candidates]
                
                # Update scan statistics
                scan.total_ssrf_candidates = all_candidates.count()
                scan.save()

            analysis_results["pipeline_results"]["heuristic"] = {
                "status": "completed",
                "total_found": all_candidates.count(),
                "after_filtering": filtered_candidates.count(),
                "will_be_processed": min(filtered_candidates.count(), max_total_candidates),
                "filters_applied": {
                    "min_risk_score": min_risk_score,
                    "max_total_candidates": max_total_candidates,
                    "auto_continue_enabled": auto_continue
                }
            }

            if not filtered_candidates.exists():
                analysis_results["message"] = "Heuristic analysis completed but no candidates met the filtering criteria"
                analysis_results["final_summary"] = {
                    "phases_completed": ["heuristic"],
                    "candidates_analyzed": 0,
                    "vulnerabilities_confirmed": 0,
                    "proofs_generated": 0
                }
                return Response(analysis_results, status=status.HTTP_200_OK)

            # =================================================================
            # PHASE 2: LLM ANALYSIS WITH AUTO-CONTINUATION BATCHING
            # =================================================================
            logger.info(f"Phase 2: Starting LLM analysis with auto-continuation for {filtered_candidates.count()} candidates")
            logger.info(f"Batch configuration: {max_candidates_per_batch} candidates per batch, {llm_batch_size} per LLM call")
            
            all_llm_results = []
            all_llm_confirmed_candidates = []
            total_llm_analyzed = 0
            all_llm_errors = []
            
            # Convert to list for batching
            candidate_list = list(filtered_candidates)
            total_candidates = len(candidate_list)
            
            # Calculate number of batches needed
            num_batches = (total_candidates + max_candidates_per_batch - 1) // max_candidates_per_batch
            logger.info(f"Will process {total_candidates} candidates in {num_batches} batches")
            
            # Process each batch automatically
            for batch_num in range(num_batches):
                start_idx = batch_num * max_candidates_per_batch
                end_idx = min(start_idx + max_candidates_per_batch, total_candidates)
                current_batch = candidate_list[start_idx:end_idx]
                batch_size = len(current_batch)
                
                logger.info(f"Processing Batch {batch_num + 1}/{num_batches}: Candidates {start_idx + 1}-{end_idx} ({batch_size} candidates)")
                
                # Verify Interactsh health before processing batch (if available)
                if oob_available and not self._verify_interactsh_health(interactsh_manager, interactsh_url):
                    logger.warning(f"Interactsh became unhealthy during batch {batch_num + 1}, OOB testing may be limited")
                    analysis_results["interactsh_info"]["health_status"] = "degraded"
                
                # LLM analysis for this batch
                batch_llm_results = []
                batch_confirmed_candidates = []
                batch_analyzed_count = 0
                batch_errors = []
                
                # Process candidates in LLM sub-batches within this batch
                for i in range(0, batch_size, llm_batch_size):
                    llm_sub_batch = current_batch[i:i + llm_batch_size]
                    sub_batch_size = len(llm_sub_batch)
                    
                    logger.info(f"LLM Sub-batch: Processing {sub_batch_size} candidates ({i + 1}-{min(i + llm_batch_size, batch_size)} of batch)")
                    
                    for candidate in llm_sub_batch:
                        try:
                            prompt = SSRFLLMDataFormatter.format_for_llm(candidate)
                            llm_response = analyze_ssrf_with_llm(prompt, llm_provider)

                            if llm_response.get('success'):
                                analysis_data = llm_response.get('analysis', {})
                                
                                llm_result_obj, created = LLMAnalysisResult.objects.update_or_create(
                                ssrf_candidate=candidate,
                                defaults={
                                    'provider': llm_response.get('provider', llm_provider),
                                    'model_used': llm_response.get('model'),
                                    'prompt_sent': prompt,
                                    'raw_llm_response': llm_response.get('raw_response'),
                                    'is_ssrf_candidate': analysis_data.get('is_ssrf_candidate', False),
                                    'primary_payload_category': analysis_data.get('primary_payload_category'),
                                    'vector_category': analysis_data.get('vector_category'),
                                    'recommended_payload': analysis_data.get('recommended_payload'),
                                    'parsed_analysis': analysis_data,
                                    'analysis_run_id': analysis_run_id,
                                    'batch_number': batch_num + 1
                                
                                }
                                )
                                
                                batch_llm_results.append(LLMAnalysisResultSerializer(llm_result_obj).data)
                                batch_analyzed_count += 1
                                
                                if llm_result_obj.is_ssrf_candidate:
                                    batch_confirmed_candidates.append((candidate, llm_result_obj))
                                    logger.info(f"LLM confirmed vulnerability in candidate {candidate.id}")
                                else:
                                    logger.debug(f"LLM rejected candidate {candidate.id}")
                            else:
                                error_msg = llm_response.get('error', 'Unknown LLM error')
                                logger.warning(f"LLM analysis failed for candidate {candidate.id}: {error_msg}")
                                batch_errors.append({
                                    "candidate_id": candidate.id,
                                    "error": error_msg,
                                    "batch_number": batch_num + 1
                                })
                                
                        except Exception as e:
                            logger.error(f"Exception in LLM analysis for candidate {candidate.id}: {e}")
                            batch_errors.append({
                                "candidate_id": candidate.id,
                                "error": str(e),
                                "batch_number": batch_num + 1
                            })

                # Add batch results to totals
                all_llm_results.extend(batch_llm_results)
                all_llm_confirmed_candidates.extend(batch_confirmed_candidates)
                total_llm_analyzed += batch_analyzed_count
                all_llm_errors.extend(batch_errors)
                
                logger.info(f"Batch {batch_num + 1} completed: {batch_analyzed_count} analyzed, {len(batch_confirmed_candidates)} confirmed vulnerable")
                
                # Optional: Add small delay between batches to prevent rate limiting
                if batch_num < num_batches - 1:  # Don't sleep after last batch
                    time.sleep(1)  # 1 second delay between batches

            logger.info(f"LLM Analysis completed: {total_llm_analyzed} total analyzed across {num_batches} batches, {len(all_llm_confirmed_candidates)} confirmed vulnerable")

            analysis_results["pipeline_results"]["llm_analysis"] = {
                "status": "completed",
                "auto_continuation_used": num_batches > 1,
                "total_batches_processed": num_batches,
                "batch_size_used": max_candidates_per_batch,
                "candidates_processed": total_llm_analyzed,
                "confirmed_vulnerable": len(all_llm_confirmed_candidates),
                "errors": len(all_llm_errors),
                "batch_details": [
                    {
                        "batch_number": i + 1,
                        "candidates_range": f"{i * max_candidates_per_batch + 1}-{min((i + 1) * max_candidates_per_batch, total_candidates)}",
                        "processed_count": min(max_candidates_per_batch, total_candidates - i * max_candidates_per_batch)
                    }
                    for i in range(num_batches)
                ],
                "results": all_llm_results,
                "error_details": all_llm_errors if all_llm_errors else None
            }

            # =================================================================
            # PHASE 2.5: UPDATE ALL PAYLOADS BEFORE DYNAMIC ANALYSIS
            # =================================================================
            if not skip_dynamic and all_llm_confirmed_candidates:
                logger.info("Phase 2.5: Starting payload update from files")
                try:
                    call_command('import_payloads')
                    logger.info("Successfully updated all SSRF payloads from files")
                except Exception as e:
                    logger.error(f"Failed to execute import_payloads command during analysis: {e}")
                    # Continue with old payloads rather than failing

            # =================================================================
            # PHASE 3: DYNAMIC ANALYSIS (ON ALL CONFIRMED CANDIDATES)
            # =================================================================
            dynamic_proofs = []
            dynamic_analyzed_count = 0
            dynamic_errors = []
            oob_tests_performed = 0

            if not skip_dynamic and all_llm_confirmed_candidates:
                logger.info(f"Phase 3: Starting dynamic analysis for {len(all_llm_confirmed_candidates)} LLM-confirmed candidates from all batches")
                
                # Final health check for Interactsh before dynamic testing
                if oob_available:
                    if self._verify_interactsh_health(interactsh_manager, interactsh_url):
                        logger.info("Interactsh is healthy for dynamic testing")
                    else:
                        logger.warning("Interactsh health degraded, OOB testing may be unreliable")
                        analysis_results["interactsh_info"]["health_status"] = "unhealthy"
                
                for candidate, llm_analysis in all_llm_confirmed_candidates:
                    try:
                        # Configure OOB server if Interactsh is available and healthy
                        oob_server_config = None
                        if oob_available and self._verify_interactsh_health(interactsh_manager, interactsh_url):
                            oob_server_config = OutOfBandServer(
                                domain=interactsh_url,
                                dns_log_endpoint=None,
                                http_log_endpoint=None,
                                verification_client=interactsh_manager,
                                api_key=None
                            )
                            oob_tests_performed += 1
                        
                        analyzer = EnhancedSSRFAnalyzer(
                            candidate=candidate, 
                            llm_analysis=llm_analysis,
                            oob_server=oob_server_config,
                            analysis_run_id=analysis_run_id
                        )
                        
                        logger.info(f"Running dynamic analysis for candidate {candidate.id} (OOB: {'enabled' if oob_server_config else 'disabled'})")
                        proofs = analyzer.run_analysis()
                        
                        if proofs:
                            serializer = SSRFProofSerializer(proofs, many=True)
                            proof_data = serializer.data
                            dynamic_proofs.extend(proof_data)
                            logger.info(f"Dynamic analysis generated {len(proofs)} proofs for candidate {candidate.id}")
                        else:
                            logger.info(f"No proofs generated for candidate {candidate.id}")
                        
                        dynamic_analyzed_count += 1
                        
                    except Exception as e:
                        logger.error(f"Error in dynamic analysis for candidate {candidate.id}: {e}")
                        dynamic_errors.append({
                            "candidate_id": candidate.id,
                            "error": str(e)
                        })

                analysis_results["pipeline_results"]["dynamic_analysis"] = {
                    "status": "completed",
                    "candidates_tested": dynamic_analyzed_count,
                    "proofs_generated": len(dynamic_proofs),
                    "errors": len(dynamic_errors),
                    "oob_tests_performed": oob_tests_performed,
                    "interactsh_used": oob_available,
                    "interactsh_healthy": self._verify_interactsh_health(interactsh_manager, interactsh_url) if oob_available else False,
                    "proofs": dynamic_proofs,
                    "error_details": dynamic_errors if dynamic_errors else None
                }
            elif skip_dynamic:
                analysis_results["pipeline_results"]["dynamic_analysis"] = {
                    "status": "skipped",
                    "reason": "skip_dynamic_analysis was set to true"
                }
            else:
                analysis_results["pipeline_results"]["dynamic_analysis"] = {
                    "status": "skipped",
                    "reason": "no LLM-confirmed vulnerable candidates found"
                }

            # =================================================================
            # UPDATE SCAN STATISTICS & FINAL SUMMARY
            # =================================================================
            scan.total_llm_analyzed = (scan.total_llm_analyzed or 0) + total_llm_analyzed
            scan.save()

            phases_completed = ["heuristic", "llm_analysis"]
            if not skip_dynamic:
                phases_completed.append("dynamic_analysis")

            analysis_results["final_summary"] = {
                "phases_completed": phases_completed,
                "candidates_analyzed": total_llm_analyzed,
                "vulnerabilities_confirmed": len(all_llm_confirmed_candidates),
                "proofs_generated": len(dynamic_proofs),
                "total_errors": len(all_llm_errors) + len(dynamic_errors),
                "oob_testing_utilized": oob_tests_performed > 0
            }

            success_message = f"Complete SSRF analysis pipeline finished. Found {len(all_llm_confirmed_candidates)} confirmed vulnerabilities with {len(dynamic_proofs)} proofs."
            if not oob_available:
                success_message += " (OOB testing was not available)"
            elif oob_tests_performed == 0:
                success_message += " (OOB testing was available but not used)"
            else:
                success_message += f" (OOB testing used for {oob_tests_performed} candidates)"

            analysis_results["message"] = success_message

            return Response(analysis_results, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Critical error in SSRF analysis pipeline for scan {scan_id}: {e}")
            return Response({
                "error": "SSRF analysis pipeline failed",
                "details": str(e),
                "partial_results": analysis_results if 'analysis_results' in locals() else {},
                "interactsh_info": {
                    "enabled": oob_available,
                    "url": interactsh_url if oob_available else "Not available",
                    "health_status": "unknown"
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        finally:
            # Always cleanup Interactsh process
            self._stop_interactsh_server(interactsh_manager)

    def _analyze_multiple_scans(self, request):
        """Complete SSRF analysis pipeline across multiple scans"""
        scan_ids = request.data.get('scan_ids', [])
        if not scan_ids:
            return Response({
                "error": "scan_ids is required for bulk analysis"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Global configuration with auto-continuation defaults
        min_risk_score = request.data.get('min_risk_score', 10)
        max_candidates_per_scan = request.data.get('max_candidates_per_scan', 30)
        max_total_per_scan = request.data.get('max_total_per_scan', 150)
        llm_batch_size = request.data.get('llm_batch_size', 5)
        llm_provider = request.data.get('llm_provider', 'openai')
        skip_dynamic = request.data.get('skip_dynamic_analysis', False)
        auto_continue = request.data.get('auto_continue', True)
        
        # Bulk-specific Interactsh settings
        interactsh_retries = request.data.get('interactsh_retries', 1)  # Fewer retries for bulk
        custom_interactsh_server = request.data.get('custom_interactsh_server', None)

        logger.info(f"Starting bulk SSRF analysis for {len(scan_ids)} scans")

        results = {}
        errors = {}

        for scan_index, scan_id in enumerate(scan_ids, 1):
            try:
                logger.info(f"Processing scan {scan_index}/{len(scan_ids)}: {scan_id}")
                
                # Create a mock request object for single scan analysis with bulk-optimized settings
                single_scan_request_data = {
                    'min_risk_score': min_risk_score,
                    'max_candidates_per_batch': max_candidates_per_scan,
                    'max_total_candidates': max_total_per_scan,
                    'llm_batch_size': llm_batch_size,
                    'llm_provider': llm_provider,
                    'skip_dynamic_analysis': skip_dynamic,
                    'auto_continue': auto_continue,
                    'reanalyze': request.data.get('reanalyze', False),
                    'interactsh_retries': interactsh_retries,
                    'custom_interactsh_server': custom_interactsh_server,
                    'force_oob_testing': False  # Don't force OOB in bulk mode
                }
                
                # Create a mock request object for single scan analysis
                from rest_framework.request import Request
                mock_request = Request(request._request)
                mock_request._full_data = single_scan_request_data
                mock_request.user = request.user
                
                response = self._analyze_single_scan(mock_request, scan_id)
                
                if response.status_code == 200:
                    results[str(scan_id)] = response.data
                    logger.info(f"Completed scan {scan_id} successfully")
                else:
                    error_msg = response.data.get('error', 'Unknown error')
                    errors[str(scan_id)] = error_msg
                    logger.error(f"Failed scan {scan_id}: {error_msg}")
                    
            except Exception as e:
                logger.error(f"Bulk analysis failed for scan {scan_id}: {e}")
                errors[str(scan_id)] = str(e)

        # Aggregate summary
        total_candidates = sum(
            res.get('final_summary', {}).get('candidates_analyzed', 0) 
            for res in results.values()
        )
        total_vulnerabilities = sum(
            res.get('final_summary', {}).get('vulnerabilities_confirmed', 0) 
            for res in results.values()
        )
        total_proofs = sum(
            res.get('final_summary', {}).get('proofs_generated', 0) 
            for res in results.values()
        )
        total_oob_used = sum(
            1 for res in results.values() 
            if res.get('final_summary', {}).get('oob_testing_utilized', False)
        )

        response_data = {
            "message": f"Bulk SSRF analysis completed for {len(scan_ids)} scans",
            "results": results,
            "errors": errors,
            "aggregate_summary": {
                "scans_requested": len(scan_ids),
                "scans_completed": len(results),
                "scans_failed": len(errors),
                "total_candidates_analyzed": total_candidates,
                "total_vulnerabilities_confirmed": total_vulnerabilities,
                "total_proofs_generated": total_proofs,
                "scans_with_oob_testing": total_oob_used
            }
        }

        if errors:
            return Response(response_data, status=status.HTTP_207_MULTI_STATUS)
        
        return Response(response_data, status=status.HTTP_200_OK)


class SSRFAnalysisHistoryView(APIView):
    """
    SSRF Analysis History and Results Viewer
    
    GET /api/scans/{scan_id}/ssrf-history/
    GET /api/ssrf/history/  (for user's complete history)
    GET /api/candidates/{candidate_id}/history/  (for specific candidate)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, scan_id=None, candidate_id=None):
        if candidate_id:
            return self._get_candidate_history(request, candidate_id)
        elif scan_id:
            return self._get_scan_history(request, scan_id)
        else:
            return self._get_user_history(request)

    def _get_scan_history(self, request, scan_id):
        """Get complete SSRF analysis history for a specific scan"""
        scan = get_object_or_404(Scan, id=scan_id, created_by=request.user)
        
        # Get all candidates for this scan
        candidates = SSRFCandidate.objects.filter(api__scan=scan).order_by('-risk_score')
        
        # Get LLM analysis results
        llm_analyses = LLMAnalysisResult.objects.filter(
            ssrf_candidate__api__scan=scan
        ).select_related('ssrf_candidate')
        
        # Get dynamic analysis proofs
        proofs = SSRFProof.objects.filter(
            ssrf_candidate__api__scan=scan
        ).select_related('ssrf_candidate')
        
        # Build comprehensive history
        history_data = {
            "scan_info": {
                "scan_id": scan.id,
                "scan_name": scan.scan_name,
                "total_apis": scan.postman_apis.count(),
                "scan_created": scan.created_at,
                "last_updated": scan.updated_at
            },
            "analysis_statistics": {
                "total_candidates_found": candidates.count(),
                "llm_analyses_performed": llm_analyses.count(),
                "confirmed_vulnerabilities": llm_analyses.filter(is_ssrf_candidate=True).count(),
                "dynamic_proofs_generated": proofs.count(),
                "highest_risk_score": candidates.aggregate(max_risk=Max('risk_score'))['max_risk'] or 0
            },
            "candidates_summary": SSRFCandidateSerializer(candidates, many=True).data,
            "llm_analysis_results": LLMAnalysisResultSerializer(llm_analyses, many=True).data,
            "dynamic_analysis_proofs": SSRFProofSerializer(proofs, many=True).data
        }
        
        # Add timeline information
        timeline = []
        if candidates.exists():
            latest_heuristic = candidates.filter(heuristic_completed_at__isnull=False).order_by('-heuristic_completed_at').first()
            if latest_heuristic:
                timeline.append({
                    "phase": "heuristic_analysis", 
                    "timestamp": latest_heuristic.heuristic_completed_at,
                    "event": f"Found {candidates.count()} SSRF candidates",
                    "analysis_run_id": latest_heuristic.analysis_run_id
                })

        for llm_result in llm_analyses.order_by('analysis_timestamp'):
            timeline.append({
                "phase": "llm_analysis",
                "timestamp": llm_result.analysis_timestamp,
                "event": f"LLM {'confirmed' if llm_result.is_ssrf_candidate else 'rejected'} candidate {llm_result.ssrf_candidate.id}"
            })

        for proof in proofs.order_by('exploitation_timestamp'):
            timeline.append({
                "phase": "dynamic_analysis",
                "timestamp": proof.exploitation_timestamp,
                "event": f"Generated proof for candidate {proof.ssrf_candidate.id}"
            })

        history_data["analysis_timeline"] = sorted(timeline, key=lambda x: x['timestamp'])
        
        return Response(history_data, status=status.HTTP_200_OK)

    def _get_candidate_history(self, request, candidate_id):
        """Get detailed history for a specific candidate"""
        candidate = get_object_or_404(SSRFCandidate, id=candidate_id)
        
        # Verify user has access to this candidate's scan
        if candidate.api.scan.created_by != request.user:
            return Response({"error": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        
        llm_analyses = LLMAnalysisResult.objects.filter(ssrf_candidate=candidate)
        proofs = SSRFProof.objects.filter(ssrf_candidate=candidate)
        
        history_data = {
            "candidate_info": SSRFCandidateSerializer(candidate).data,
            "scan_info": {
                "scan_id": candidate.api.scan.id,
                "scan_name": candidate.api.scan.scan_name
            },
            "analysis_history": {
                "llm_analyses": LLMAnalysisResultSerializer(llm_analyses, many=True).data,
                "dynamic_proofs": SSRFProofSerializer(proofs, many=True).data
            },
            "summary": {
                "llm_analyses_count": llm_analyses.count(),
                "confirmed_vulnerable": llm_analyses.filter(is_ssrf_candidate=True).exists(),
                "proofs_generated": proofs.count()
            }
        }
        
        return Response(history_data, status=status.HTTP_200_OK)

    def _get_user_history(self, request):
        """Get complete SSRF analysis history for the authenticated user"""
        user_scans = Scan.objects.filter(created_by=request.user)
        
        # Aggregate statistics
        total_candidates = SSRFCandidate.objects.filter(api__scan__in=user_scans).count()
        total_llm_analyses = LLMAnalysisResult.objects.filter(
            ssrf_candidate__api__scan__in=user_scans
        ).count()
        confirmed_vulnerabilities = LLMAnalysisResult.objects.filter(
            ssrf_candidate__api__scan__in=user_scans,
            is_ssrf_candidate=True
        ).count()
        total_proofs = SSRFProof.objects.filter(
            ssrf_candidate__api__scan__in=user_scans
        ).count()
        
        # Recent activity (last 10 scans with SSRF analysis)
        recent_scans_with_ssrf = user_scans.annotate(
            candidate_count=Count('postman_apis__ssrf_candidates'),
            latest_analysis=Max('postman_apis__ssrf_candidates__heuristic_completed_at')
        ).filter(candidate_count__gt=0).order_by('-latest_analysis')[:10]
        
        history_data = {
            "user_statistics": {
                "total_scans_with_ssrf_analysis": recent_scans_with_ssrf.count(),
                "total_candidates_found": total_candidates,
                "total_llm_analyses": total_llm_analyses,
                "confirmed_vulnerabilities": confirmed_vulnerabilities,
                "total_proofs_generated": total_proofs
            },
            "recent_scans": [
                {
                    "scan_id": scan.id,
                    "scan_name": scan.scan_name,
                    "last_updated": scan.updated_at,
                    "candidates_count": scan.candidate_count
                }
                for scan in recent_scans_with_ssrf
            ]
        }
        
        return Response(history_data, status=status.HTTP_200_OK)