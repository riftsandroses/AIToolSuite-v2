import React, { useState, useEffect, useCallback } from 'react';
import {
    Shield, BarChart3, Clock, Plus, Trash2, Edit3, Download,
    ChevronRight, AlertTriangle, RefreshCw, ArrowLeft, Eye,
    FileText, Lock, Server, X, ChevronDown, ChevronUp, History,
    ClipboardList, ShieldAlert, ShieldCheck, Info, Save,
    Upload, Network, Settings, AlertCircle, Activity, Zap,
    Search, LayoutDashboard, Home,
} from 'lucide-react';

import {
    createAssessment, listAssessments, getAssessmentDetails,
    updateAssessment, deleteAssessment, downloadExcelReport,
    getAssessmentHistory, getStatistics,
    listVulnerabilities, updateVulnerabilityStatus,
    listControlsForVulnerability, createControl, updateControl,
    getControlUpdateHistory, deleteControl,
} from './api';

// ─── Global Styles ────────────────────────────────────────────────────────────
const GlobalStyles = () => (
    <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        :root {
            --bg-base:   #080e1a;
            --bg-card:   #0d1525;
            --bg-card2:  #111e33;
            --bg-input:  #0a1222;
            --bg-hover:  #152035;
            --accent:       #3b8ef0;
            --accent-dim:   #1e6fd9;
            --accent-sub:   rgba(59,142,240,0.12);
            /* Text — high contrast on dark */
            --t1: #f0f4ff;
            --t2: #c8d8f0;
            --t3: #7a9abf;
            --t4: #3d5a7a;
            /* Borders */
            --b1: rgba(255,255,255,0.12);
            --b2: rgba(59,142,240,0.3);
            --b3: rgba(255,255,255,0.06);
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        .ara-root {
            font-family: 'DM Sans', sans-serif;
            background: var(--bg-base);
            min-height: 100vh;
            color: var(--t2);
        }

        /* ── Background depth ── */
        .ara-bg {
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background:
                radial-gradient(ellipse 60% 40% at 8% 0%, rgba(20,70,160,0.13) 0%, transparent 55%),
                radial-gradient(ellipse 50% 38% at 92% 100%, rgba(15,80,180,0.1) 0%, transparent 55%);
        }
        .ara-grid {
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background-image:
                linear-gradient(rgba(59,142,240,0.022) 1px, transparent 1px),
                linear-gradient(90deg, rgba(59,142,240,0.022) 1px, transparent 1px);
            background-size: 56px 56px;
            mask-image: radial-gradient(ellipse 100% 65% at 50% 0%, black 0%, transparent 100%);
        }
        .ara-orb { position: fixed; border-radius: 50%; pointer-events: none; z-index: 0; filter: blur(110px); animation: orbFloat 24s ease-in-out infinite; }
        .ara-orb-1 { width: 520px; height: 520px; background: rgba(18,65,155,0.16); top: -240px; left: -110px; animation-delay: 0s; }
        .ara-orb-2 { width: 400px; height: 400px; background: rgba(14,75,180,0.12); bottom: -150px; right: -90px; animation-delay: -10s; }
        @keyframes orbFloat { 0%,100% { transform:translate(0,0); } 50% { transform:translate(18px,-18px); } }

        /* ── Cards / surfaces ── */
        .card  { background: var(--bg-card);  border: 1px solid var(--b1); border-radius: 14px; }
        .card2 { background: var(--bg-card2); border: 1px solid var(--b1); border-radius: 14px; }
        .card-accent { background: var(--bg-card); border: 1px solid var(--b2); border-radius: 14px; }

        /* ── Stat card ── */
        .stat-card { position: relative; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .stat-card::before { content:''; position:absolute; inset:0; background:linear-gradient(135deg,rgba(255,255,255,0.025) 0%,transparent 55%); pointer-events:none; border-radius:inherit; }

        /* ── Shimmer ── */
        .shimmer { position:relative; overflow:hidden; }
        .shimmer::after { content:''; position:absolute; left:-100%; top:0; width:50%; height:100%; background:linear-gradient(90deg,transparent,rgba(59,142,240,0.055),transparent); transition:left 0.5s; }
        .shimmer:hover::after { left:160%; }

        /* ── Nav ── */
        .nav-glow { box-shadow: 0 1px 0 rgba(59,142,240,0.3); }

        /* ── Sidebar items ── */
        .s-item { transition: all 0.15s; border-left: 2px solid transparent; border-radius: 10px; cursor: pointer; }
        .s-item:hover { background: rgba(59,142,240,0.07); border-left-color: rgba(59,142,240,0.35) !important; }
        .s-item.active { background: rgba(59,142,240,0.13); border-left-color: var(--accent) !important; }
        .s-item:hover .s-del { opacity: 1 !important; }
        .s-del { opacity: 0 !important; transition: opacity 0.15s !important; }

        /* ── Vuln rows ── */
        .vuln-row { transition: all 0.18s; border-left: 3px solid transparent; }
        .vuln-row:hover { background: rgba(255,255,255,0.02) !important; }
        .vuln-row.critical { border-left-color: #ef4444 !important; }
        .vuln-row.high     { border-left-color: #f97316 !important; }
        .vuln-row.medium   { border-left-color: #eab308 !important; }
        .vuln-row.low      { border-left-color: #22c55e !important; }

        /* ── Detail tabs ── */
        .d-tab { transition: all 0.15s; border-bottom: 2px solid transparent; cursor: pointer; border-radius: 8px 8px 0 0; }
        .d-tab:hover { color: var(--t2) !important; background: rgba(255,255,255,0.03) !important; }
        .d-tab.active { border-bottom-color: var(--accent) !important; color: var(--accent) !important; background: rgba(59,142,240,0.08) !important; }

        /* ── Badge pulse ── */
        .badge-critical { animation: pulseCrit 2s ease-in-out infinite; }
        @keyframes pulseCrit { 0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0.4);}50%{box-shadow:0 0 0 4px rgba(239,68,68,0);} }

        /* ── Inputs ── */
        .ara-input {
            width: 100%; padding: 11px 14px;
            background: var(--bg-input);
            border: 1.5px solid rgba(255,255,255,0.11);
            border-radius: 10px;
            color: var(--t1);
            font-family: 'DM Sans', sans-serif;
            font-size: 13.5px; font-weight: 500;
            outline: none;
            transition: border-color 0.18s, background 0.18s, box-shadow 0.18s;
            line-height: 1.5;
        }
        .ara-input:hover:not(:focus) { border-color: rgba(255,255,255,0.2); background: #0c1528; }
        .ara-input:focus {
            border-color: var(--accent) !important;
            background: rgba(20,56,110,0.18) !important;
            box-shadow: 0 0 0 3px rgba(59,142,240,0.16);
        }
        .ara-input::placeholder { color: var(--t4); font-weight: 400; }
        .ara-input option { background: #0d1525; color: var(--t1); }
        textarea.ara-input { resize: vertical; line-height: 1.65; min-height: 80px; }
        .has-icon .ara-input { padding-left: 38px; }

        /* ── Field icon ── */
        .f-icon { position:absolute; left:12px; top:50%; transform:translateY(-50%); color:var(--t4); pointer-events:none; transition:color 0.18s; z-index:1; }
        .f-wrap:focus-within .f-icon { color: var(--accent) !important; }

        /* ── Field label ── */
        .f-label {
            display: flex; align-items: center; gap: 7px;
            font-size: 13px; font-weight: 700; color: var(--t2);
            margin-bottom: 7px; letter-spacing: 0.005em;
            font-family: 'DM Sans', sans-serif; user-select: none; cursor: default;
        }
        .f-label-bar { width: 3px; height: 13px; border-radius: 2px; background: var(--accent-dim); flex-shrink: 0; }
        .f-label .req { color: #f87171; margin-left: 1px; font-size: 14px; line-height: 1; }

        /* ── Upload zone ── */
        .upload-zone { border: 1.5px dashed rgba(255,255,255,0.12); border-radius: 10px; padding: 14px; background: var(--bg-input); transition: all 0.2s; cursor: pointer; }
        .upload-zone:hover  { border-color: var(--accent); background: rgba(20,56,110,0.12); }
        .upload-zone.has-f  { border-color: var(--accent); background: rgba(20,56,110,0.1); border-style: solid; }
        .upload-zone.req-empty { border-color: rgba(239,68,68,0.5); background: rgba(239,68,68,0.04); }

        /* ── Control cards ── */
        .ctrl-card { transition: background 0.15s; }
        .ctrl-card:hover { background: rgba(255,255,255,0.025) !important; }

        /* ── Search input ── */
        .search-input { background: rgba(255,255,255,0.04); border: 1px solid var(--b1); border-radius: 8px; color: var(--t1); font-size: 12.5px; padding: 7px 10px 7px 32px; outline: none; width: 100%; font-family: 'DM Sans', sans-serif; transition: all 0.15s; }
        .search-input:focus { border-color: var(--b2); background: rgba(59,142,240,0.06); }
        .search-input::placeholder { color: var(--t4); }

        /* ── Dividers ── */
        .divider      { height:1px; background:linear-gradient(90deg,transparent,var(--b1),transparent); }
        .divider-blue { height:1px; background:linear-gradient(90deg,transparent,rgba(59,142,240,0.25),transparent); }

        /* ── Animations ── */
        .fade-up { animation: fadeUp 0.38s cubic-bezier(0.22,1,0.36,1) both; }
        .d1{animation-delay:0.05s;} .d2{animation-delay:0.1s;} .d3{animation-delay:0.15s;} .d4{animation-delay:0.2s;}
        @keyframes fadeUp { from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);} }
        @keyframes spin { to{transform:rotate(360deg);} }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar { width:5px; height:5px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:rgba(59,142,240,0.22); border-radius:4px; }
        ::-webkit-scrollbar-thumb:hover { background:rgba(59,142,240,0.42); }
    `}</style>
);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmtDate = d => d ? new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—';
const fmtDateTime = d => d ? new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const fmtStatus = s => (s || '—').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

const RISK = {
    critical: { bg: 'rgba(239,68,68,0.15)', text: '#fca5a5', border: 'rgba(239,68,68,0.42)', dot: '#ef4444' },
    high: { bg: 'rgba(249,115,22,0.15)', text: '#fdba74', border: 'rgba(249,115,22,0.42)', dot: '#f97316' },
    medium: { bg: 'rgba(234,179,8,0.14)', text: '#fde047', border: 'rgba(234,179,8,0.38)', dot: '#eab308' },
    low: { bg: 'rgba(34,197,94,0.13)', text: '#86efac', border: 'rgba(34,197,94,0.38)', dot: '#22c55e' },
    default: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1', border: 'rgba(148,163,184,0.3)', dot: '#94a3b8' },
};
const riskMeta = l => RISK[(l || '').toLowerCase()] || RISK.default;

const STATUS_META = {
    open: { bg: 'rgba(239,68,68,0.14)', text: '#fca5a5', border: 'rgba(239,68,68,0.38)' },
    in_progress: { bg: 'rgba(251,191,36,0.14)', text: '#fde68a', border: 'rgba(251,191,36,0.38)' },
    fixed: { bg: 'rgba(34,197,94,0.14)', text: '#86efac', border: 'rgba(34,197,94,0.38)' },
    completed: { bg: 'rgba(59,142,240,0.14)', text: '#93c5fd', border: 'rgba(59,142,240,0.38)' },
    verified: { bg: 'rgba(99,179,237,0.14)', text: '#bae6fd', border: 'rgba(99,179,237,0.38)' },
    implemented: { bg: 'rgba(59,142,240,0.14)', text: '#7dd3fc', border: 'rgba(59,142,240,0.38)' },
    pending: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1', border: 'rgba(148,163,184,0.3)' },
    failed: { bg: 'rgba(239,68,68,0.14)', text: '#fca5a5', border: 'rgba(239,68,68,0.38)' },
};
const statusMeta = s => STATUS_META[(s || '').toLowerCase()] || STATUS_META.pending;

// ─── Field Definitions ────────────────────────────────────────────────────────
const STEPS = [
    { label: 'App & Architecture', icon: Server },
    { label: 'Business Context', icon: FileText },
    { label: 'Infrastructure', icon: Network },
    { label: 'Security Controls', icon: Lock },
    { label: 'Ops & Risk', icon: Settings },
];

const ALL_FIELDS = [
    ['application_purpose', 'Application Purpose', 'textarea', 1],
    ['business_objectives', 'Business Objectives', 'textarea', 1],
    ['business_criticality', 'Business Criticality', 'select', 1, ['Low', 'Medium', 'High', 'Critical']],
    ['impact_of_failure', 'Impact of Failure', 'textarea', 1],
    ['supported_business_processes', 'Supported Business Processes', 'text', 1],
    ['data_sensitivity', 'Data Sensitivity', 'select', 1, ['Public', 'Internal', 'Confidential', 'Highly sensitive financial data', 'Restricted']],
    ['data_classification_levels', 'Data Classification Levels', 'text', 1],
    ['regulatory_requirements', 'Regulatory Requirements', 'text', 1],
    ['compliance_requirements', 'Compliance Requirements', 'text', 1],
    ['stakeholders', 'Stakeholders', 'text', 1],
    ['system_owners', 'System Owners', 'text', 1],
    ['risk_tolerance', 'Risk Tolerance', 'select', 1, ['Low', 'Medium', 'High']],
    ['risk_acceptance_criteria', 'Risk Acceptance Criteria', 'text', 1],
    ['application_type', 'Application Type', 'select', 0, ['Web application', 'Mobile application', 'Desktop application', 'API/Backend Service', 'Hybrid']],
    ['usage_model', 'Usage Model', 'text', 0],
    ['functional_overview', 'Functional Overview', 'textarea', 0],
    ['major_modules', 'Major Modules', 'text', 0],
    ['user_roles', 'User Roles', 'text', 0],
    ['access_types', 'Access Types', 'text', 0],
    ['expected_traffic', 'Expected Traffic', 'text', 0],
    ['load_patterns', 'Load Patterns', 'text', 0],
    ['deployment_model', 'Deployment Model', 'select', 0, ['Cloud hosted', 'On-premise', 'Hybrid', 'SaaS']],
    ['programming_languages', 'Programming Languages', 'text', 0],
    ['frameworks_versions', 'Frameworks & Versions', 'text', 0],
    ['libraries_packages', 'Libraries & Packages', 'text', 0],
    ['runtime_environments', 'Runtime Environments', 'text', 0],
    ['databases', 'Databases', 'text', 0],
    ['storage_systems', 'Storage Systems', 'text', 0],
    ['middleware_components', 'Middleware Components', 'text', 0],
    ['message_queues', 'Message Queues', 'text', 0],
    ['api_gateways', 'API Gateways', 'text', 0],
    ['web_servers', 'Web Servers', 'text', 0],
    ['application_servers', 'Application Servers', 'text', 0],
    ['containerization_platforms', 'Containerization Platforms', 'text', 0],
    ['orchestration_platforms', 'Orchestration Platforms', 'text', 0],
    ['trust_boundaries', 'Trust Boundaries', 'text', 0],
    ['component_interaction', 'Component Interaction', 'text', 0],
    ['design_patterns', 'Design Patterns', 'text', 0],
    ['hosting_environment', 'Hosting Environment', 'text', 2],
    ['cloud_services', 'Cloud Services', 'text', 2],
    ['network_architecture', 'Network Architecture', 'text', 2],
    ['network_topology', 'Network Topology', 'text', 2],
    ['network_segmentation', 'Network Segmentation', 'text', 2],
    ['subnets', 'Subnets', 'text', 2],
    ['load_balancers', 'Load Balancers', 'text', 2],
    ['traffic_routing', 'Traffic Routing', 'text', 2],
    ['firewall_config', 'Firewall Config', 'text', 2],
    ['waf_config', 'WAF Config', 'text', 2],
    ['cdn_usage', 'CDN Usage', 'text', 2],
    ['regions', 'Regions', 'text', 2],
    ['availability_zones', 'Availability Zones', 'text', 2],
    ['high_availability_design', 'High Availability Design', 'text', 2],
    ['backup_architecture', 'Backup Architecture', 'text', 2],
    ['disaster_recovery_setup', 'Disaster Recovery Setup', 'text', 2],
    ['fault_tolerance_mechanisms', 'Fault Tolerance Mechanisms', 'text', 2],
    ['redundancy_design', 'Redundancy Design', 'text', 2],
    ['auto_scaling_config', 'Auto Scaling Config', 'text', 2],
    ['retry_logic', 'Retry Logic', 'text', 2],
    ['circuit_breaker_logic', 'Circuit Breaker Logic', 'text', 2],
    ['rto_targets', 'RTO Targets', 'text', 2],
    ['rpo_targets', 'RPO Targets', 'text', 2],
    ['authentication_mechanisms', 'Authentication Mechanisms', 'text', 3],
    ['authorization_model', 'Authorization Model', 'text', 3],
    ['sso_federation', 'SSO / Federation', 'text', 3],
    ['mfa_enforcement', 'MFA Enforcement', 'text', 3],
    ['service_authentication', 'Service Authentication', 'text', 3],
    ['secrets_management', 'Secrets Management', 'text', 3],
    ['key_management', 'Key Management', 'text', 3],
    ['privileged_access_controls', 'Privileged Access Controls', 'text', 3],
    ['account_provisioning', 'Account Provisioning', 'text', 3],
    ['account_deprovisioning', 'Account Deprovisioning', 'text', 3],
    ['data_types_processed', 'Data Types Processed', 'text', 3],
    ['data_types_stored', 'Data Types Stored', 'text', 3],
    ['sensitive_data_locations', 'Sensitive Data Locations', 'text', 3],
    ['data_flow_paths', 'Data Flow Paths', 'text', 3],
    ['encryption_at_rest', 'Encryption at Rest', 'text', 3],
    ['encryption_in_transit', 'Encryption in Transit', 'text', 3],
    ['key_rotation_practices', 'Key Rotation Practices', 'text', 3],
    ['data_retention_policies', 'Data Retention Policies', 'text', 3],
    ['data_masking', 'Data Masking', 'text', 3],
    ['data_tokenization', 'Data Tokenization', 'text', 3],
    ['sensitive_data_in_logs', 'Sensitive Data in Logs', 'text', 3],
    ['data_import_paths', 'Data Import Paths', 'text', 3],
    ['data_export_paths', 'Data Export Paths', 'text', 3],
    ['third_party_integrations', 'Third-Party Integrations', 'text', 3],
    ['external_dependencies', 'External Dependencies', 'text', 3],
    ['internal_apis', 'Internal APIs', 'text', 3],
    ['external_apis', 'External APIs', 'text', 3],
    ['partner_integrations', 'Partner Integrations', 'text', 3],
    ['vendor_integrations', 'Vendor Integrations', 'text', 3],
    ['webhooks', 'Webhooks', 'text', 3],
    ['callbacks', 'Callbacks', 'text', 3],
    ['file_transfer_interfaces', 'File Transfer Interfaces', 'text', 3],
    ['api_authentication', 'API Authentication', 'text', 3],
    ['rate_limiting', 'Rate Limiting', 'text', 3],
    ['input_validation_controls', 'Input Validation Controls', 'text', 3],
    ['secure_coding_standards', 'Secure Coding Standards', 'text', 3],
    ['threat_modeling_status', 'Threat Modeling Status', 'text', 3],
    ['security_design_reviews', 'Security Design Reviews', 'text', 3],
    ['output_encoding_controls', 'Output Encoding Controls', 'text', 3],
    ['error_handling_approach', 'Error Handling Approach', 'text', 3],
    ['session_management', 'Session Management', 'text', 3],
    ['injection_protections', 'Injection Protections', 'text', 3],
    ['xss_protections', 'XSS Protections', 'text', 3],
    ['dependency_scanning', 'Dependency Scanning', 'text', 3],
    ['container_scanning', 'Container Scanning', 'text', 3],
    ['image_scanning', 'Image Scanning', 'text', 3],
    ['runtime_security_controls', 'Runtime Security Controls', 'text', 3],
    ['network_protocols', 'Network Protocols', 'text', 3],
    ['open_ports', 'Open Ports', 'text', 3],
    ['exposed_services', 'Exposed Services', 'text', 3],
    ['tls_configuration', 'TLS Configuration', 'text', 3],
    ['certificate_management', 'Certificate Management', 'text', 3],
    ['internal_external_exposure', 'Internal/External Exposure', 'text', 3],
    ['zero_trust_controls', 'Zero Trust Controls', 'text', 3],
    ['service_mesh_controls', 'Service Mesh Controls', 'text', 3],
    ['sdlc_methodology', 'SDLC Methodology', 'text', 4],
    ['code_review_requirements', 'Code Review Requirements', 'text', 4],
    ['static_analysis_tooling', 'Static Analysis Tooling', 'text', 4],
    ['dynamic_testing_tooling', 'Dynamic Testing Tooling', 'text', 4],
    ['sca_tooling', 'SCA Tooling', 'text', 4],
    ['cicd_pipeline_design', 'CI/CD Pipeline Design', 'text', 4],
    ['build_artifact_controls', 'Build Artifact Controls', 'text', 4],
    ['environment_separation', 'Environment Separation', 'text', 4],
    ['secrets_handling_pipelines', 'Secrets Handling (Pipelines)', 'text', 4],
    ['logging_architecture', 'Logging Architecture', 'text', 4],
    ['security_event_logging', 'Security Event Logging', 'text', 4],
    ['centralized_log_collection', 'Centralized Log Collection', 'text', 4],
    ['siem_integration', 'SIEM Integration', 'text', 4],
    ['alerting_rules', 'Alerting Rules', 'text', 4],
    ['detection_rules', 'Detection Rules', 'text', 4],
    ['monitoring_coverage', 'Monitoring Coverage', 'text', 4],
    ['audit_trail', 'Audit Trail', 'text', 4],
    ['log_retention_periods', 'Log Retention Periods', 'text', 4],
    ['patch_management', 'Patch Management', 'text', 4],
    ['configuration_management', 'Configuration Management', 'text', 4],
    ['change_management', 'Change Management', 'text', 4],
    ['incident_response_procedures', 'Incident Response Procedures', 'text', 4],
    ['operational_runbooks', 'Operational Runbooks', 'text', 4],
    ['support_maintenance_model', 'Support & Maintenance Model', 'text', 4],
    ['backup_restore_testing', 'Backup & Restore Testing', 'text', 4],
    ['third_party_services', 'Third-Party Services', 'text', 4],
    ['vendor_risk_assessments', 'Vendor Risk Assessments', 'text', 4],
    ['open_source_components', 'Open Source Components', 'text', 4],
    ['license_risks', 'License Risks', 'text', 4],
    ['dependency_update_cadence', 'Dependency Update Cadence', 'text', 4],
    ['component_support_status', 'Component Support Status', 'text', 4],
    ['compliance_standards', 'Compliance Standards', 'text', 4],
    ['control_framework_mappings', 'Control Framework Mappings', 'text', 4],
    ['prior_audit_findings', 'Prior Audit Findings', 'text', 4],
    ['policy_exceptions', 'Policy Exceptions', 'text', 4],
    ['existing_risk_register', 'Existing Risk Register', 'text', 4],
    ['known_vulnerabilities', 'Known Findings', 'textarea', 4],
    ['accepted_risks', 'Accepted Risks', 'text', 4],
    ['architecture_assumptions', 'Architecture Assumptions', 'text', 4],
    ['design_constraints', 'Design Constraints', 'text', 4],
    ['technical_debt_areas', 'Technical Debt Areas', 'textarea', 4],
];

const FIELD_ICONS = { application_purpose: FileText, business_objectives: FileText, business_criticality: AlertTriangle, impact_of_failure: AlertCircle, data_sensitivity: Lock, regulatory_requirements: ClipboardList, compliance_requirements: ClipboardList, stakeholders: Eye, system_owners: Shield, risk_tolerance: AlertTriangle, authentication_mechanisms: Lock, authorization_model: Lock, encryption_at_rest: Lock, encryption_in_transit: Lock, network_architecture: Network, hosting_environment: Server, cloud_services: Server, databases: Server, tls_configuration: Lock, secrets_management: Lock, key_management: Lock };

// ─── Shared UI ────────────────────────────────────────────────────────────────
const Spinner = ({ size = 'sm' }) => (
    <div style={{ width: size === 'sm' ? 16 : 30, height: size === 'sm' ? 16 : 30, border: '2px solid rgba(59,142,240,0.18)', borderTop: '2px solid #3b8ef0', borderRadius: '50%', animation: 'spin 0.7s linear infinite', flexShrink: 0 }} />
);

const Badge = ({ label }) => {
    const r = riskMeta(label);
    return (
        <span className={(label || '').toLowerCase() === 'critical' ? 'badge-critical' : ''} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 5, background: r.bg, border: `1px solid ${r.border}`, color: r.text, fontSize: 10, fontWeight: 700, letterSpacing: '0.05em', fontFamily: "'JetBrains Mono',monospace" }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: r.dot, flexShrink: 0 }} />
            {(label || '—').toUpperCase()}
        </span>
    );
};

const StatusPill = ({ status }) => {
    const m = statusMeta(status);
    return <span style={{ display: 'inline-flex', alignItems: 'center', padding: '3px 10px', borderRadius: 5, background: m.bg, border: `1px solid ${m.border}`, color: m.text, fontSize: 11, fontWeight: 700 }}>{fmtStatus(status)}</span>;
};

const SectionLabel = ({ children }) => (
    <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 600, color: 'rgba(59,142,240,0.65)', letterSpacing: '0.12em', textTransform: 'uppercase', margin: '0 0 10px' }}>{children}</p>
);

// ── Breadcrumb ──
const Breadcrumb = ({ view, assessmentName, onDashboard }) => {
    const crumbs = [{ key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard }];
    if (view === 'create') crumbs.push({ key: 'create', label: 'New Assessment', icon: Plus });
    if (view === 'detail') crumbs.push({ key: 'detail', label: assessmentName || 'Assessment Details', icon: FileText });
    return (
        <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {crumbs.map((c, i) => {
                const Icon = c.icon; const isLast = i === crumbs.length - 1;
                return (
                    <React.Fragment key={c.key}>
                        {i > 0 && <ChevronRight size={12} color="var(--t4)" style={{ flexShrink: 0 }} />}
                        <button onClick={() => !isLast && onDashboard()} style={{ display: 'flex', alignItems: 'center', gap: 5, background: isLast ? 'rgba(59,142,240,0.1)' : 'transparent', border: 'none', cursor: isLast ? 'default' : 'pointer', padding: '4px 9px', borderRadius: 7, color: isLast ? 'var(--t1)' : 'var(--t3)', fontWeight: isLast ? 700 : 500, fontSize: 13, fontFamily: "'DM Sans',sans-serif", transition: 'all 0.15s' }}
                            onMouseEnter={e => { if (!isLast) e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; }}
                            onMouseLeave={e => { if (!isLast) e.currentTarget.style.background = 'transparent'; }}>
                            <Icon size={13} />{c.label}
                        </button>
                    </React.Fragment>
                );
            })}
        </nav>
    );
};

const Modal = ({ open, onClose, title, children, wide = false }) => {
    if (!open) return null;
    return (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
            <div style={{ position: 'absolute', inset: 0, background: 'rgba(4,8,20,0.92)', backdropFilter: 'blur(10px)' }} onClick={onClose} />
            <div className="card2" style={{ position: 'relative', display: 'flex', flexDirection: 'column', maxHeight: '90vh', width: '100%', maxWidth: wide ? 1000 : 520, boxShadow: '0 0 0 1px rgba(59,142,240,0.15), 0 24px 56px rgba(0,0,0,0.8)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 24px', borderBottom: '1px solid var(--b1)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ width: 3, height: 20, background: 'linear-gradient(to bottom,#1e6fd9,#3b8ef0)', borderRadius: 2 }} />
                        <h2 style={{ fontSize: 16, fontWeight: 800, color: 'var(--t1)', margin: 0 }}>{title}</h2>
                    </div>
                    <button onClick={onClose} style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid var(--b1)', borderRadius: 8, padding: 7, cursor: 'pointer', color: 'var(--t3)', display: 'flex', transition: 'all 0.15s' }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.12)'; e.currentTarget.style.color = '#fca5a5'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--t3)'; }}>
                        <X size={16} />
                    </button>
                </div>
                <div style={{ overflowY: 'auto', padding: 24, flex: 1 }}>{children}</div>
            </div>
        </div>
    );
};

const Btn = ({ children, onClick, variant = 'primary', size = 'md', disabled, loading, type = 'button' }) => {
    const [hov, setHov] = useState(false);
    const sz = { sm: { fontSize: 12, padding: '7px 14px' }, md: { fontSize: 13, padding: '10px 20px' }, lg: { fontSize: 14, padding: '12px 28px' } };
    const base = { display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: "'DM Sans',sans-serif", fontWeight: 700, borderRadius: 9, transition: 'all 0.18s', cursor: disabled || loading ? 'not-allowed' : 'pointer', border: 'none', outline: 'none', opacity: disabled || loading ? 0.5 : 1, ...sz[size] };
    const V = { primary: { background: 'linear-gradient(135deg,#1454b8,#2e7de0)', color: '#fff', boxShadow: '0 4px 16px rgba(30,111,217,0.38)' }, secondary: { background: 'rgba(255,255,255,0.07)', border: '1px solid rgba(255,255,255,0.15)', color: 'var(--t2)' }, danger: { background: 'rgba(239,68,68,0.13)', border: '1px solid rgba(239,68,68,0.38)', color: '#fca5a5' }, ghost: { background: 'transparent', color: 'var(--t3)' }, success: { background: 'rgba(34,197,94,0.13)', border: '1px solid rgba(34,197,94,0.38)', color: '#86efac' } };
    const H = { primary: { filter: 'brightness(1.1)', boxShadow: '0 6px 24px rgba(30,111,217,0.48)', transform: 'translateY(-1px)' }, secondary: { background: 'rgba(255,255,255,0.12)', color: 'var(--t1)' }, danger: { background: 'rgba(239,68,68,0.22)', color: '#fca5a5' }, ghost: { background: 'rgba(255,255,255,0.07)', color: 'var(--t1)' }, success: { background: 'rgba(34,197,94,0.22)', color: '#86efac' } };
    return <button type={type} onClick={onClick} disabled={disabled || loading} style={{ ...base, ...V[variant], ...(hov ? H[variant] : {}) }} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}>{loading && <Spinner />}{children}</button>;
};

const EmptyState = ({ icon: Icon = FileText, title, subtitle }) => (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '52px 24px', textAlign: 'center' }}>
        <div style={{ width: 56, height: 56, borderRadius: 14, marginBottom: 14, background: 'rgba(59,142,240,0.07)', border: '1px solid rgba(59,142,240,0.18)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon size={22} color="rgba(59,142,240,0.55)" />
        </div>
        <p style={{ color: 'var(--t1)', fontWeight: 700, fontSize: 14, margin: '0 0 5px' }}>{title}</p>
        {subtitle && <p style={{ color: 'var(--t4)', fontSize: 12, margin: 0 }}>{subtitle}</p>}
    </div>
);

// ─── Form Inputs ──────────────────────────────────────────────────────────────
const FLabel = ({ label, required, htmlFor }) => (
    <label className="f-label" htmlFor={htmlFor}>
        <span className="f-label-bar" />
        {label}
        {required && <span className="req">*</span>}
    </label>
);

const FInput = ({ label, name, value, onChange, required }) => {
    const Icon = FIELD_ICONS[name];
    return (
        <div>
            <FLabel label={label} required={required} htmlFor={name} />
            <div className={`f-wrap${Icon ? ' has-icon' : ''}`} style={{ position: 'relative' }}>
                {Icon && <span className="f-icon"><Icon size={14} /></span>}
                <input id={name} className="ara-input" type="text" name={name} value={value || ''} onChange={onChange} placeholder={`Enter ${label.toLowerCase()}…`} required={required} />
            </div>
        </div>
    );
};

const FTextarea = ({ label, name, value, onChange, rows = 3 }) => (
    <div>
        {label && <FLabel label={label} htmlFor={name} />}
        <div className="f-wrap" style={{ position: 'relative' }}>
            <textarea id={name} className="ara-input" name={name} value={value || ''} onChange={onChange} rows={rows} placeholder={label ? `Describe ${label.toLowerCase()}…` : ''} />
        </div>
    </div>
);

const FSelect = ({ label, name, value, onChange, options }) => (
    <div>
        {label && <FLabel label={label} htmlFor={name} />}
        <div className="f-wrap" style={{ position: 'relative' }}>
            <select id={name} className="ara-input" name={name} value={value || ''} onChange={onChange} style={{ appearance: 'none', cursor: 'pointer', paddingRight: 36 }}>
                <option value="">— Select an option —</option>
                {options.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
            <ChevronDown size={14} color="var(--t4)" style={{ position: 'absolute', right: 13, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
        </div>
    </div>
);

const FFile = ({ label, name, file, onChange, required }) => (
    <div>
        <FLabel label={label} required={required} htmlFor={name} />
        <div className={`upload-zone${file ? ' has-f' : ''}${required && !file ? ' req-empty' : ''}`}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
                <div style={{ width: 36, height: 36, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: file ? 'rgba(59,142,240,0.16)' : 'rgba(255,255,255,0.05)', border: `1px solid ${file ? 'rgba(59,142,240,0.4)' : 'rgba(255,255,255,0.1)'}`, flexShrink: 0, transition: 'all 0.2s' }}>
                    <Upload size={15} color={file ? '#3b8ef0' : 'var(--t4)'} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 700, color: file ? '#93c5fd' : 'var(--t2)', margin: '0 0 2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {file ? file.name : `Choose ${required ? 'required ' : ''}file`}
                    </p>
                    <p style={{ fontSize: 11, color: 'var(--t4)', margin: 0 }}>{file ? `${(file.size / 1024).toFixed(1)} KB` : 'PNG, JPG, PDF, SVG'}</p>
                </div>
                {file && (
                    <button type="button" onClick={e => { e.preventDefault(); onChange({ target: { files: [] } }); }} style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid var(--b1)', borderRadius: 7, padding: '5px 6px', cursor: 'pointer', color: 'var(--t3)', display: 'flex', flexShrink: 0, transition: 'all 0.15s' }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.12)'; e.currentTarget.style.color = '#fca5a5'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--t3)'; }}>
                        <X size={13} />
                    </button>
                )}
                <input type="file" name={name} accept="image/*,.pdf,.svg" onChange={onChange} style={{ display: 'none' }} />
            </label>
        </div>
    </div>
);

// ─── Assessment Form ──────────────────────────────────────────────────────────
const AssessmentForm = ({ initial, onSubmit, onCancel, loading }) => {
    const [step, setStep] = useState(0);
    const [data, setData] = useState(() => { const d = {}; ALL_FIELDS.forEach(([k]) => { d[k] = initial?.[k] ?? ''; }); return d; });
    const [files, setFiles] = useState({ architecture_diagram: null, high_level_architecture: null, logical_architecture: null, physical_architecture: null, data_flow_diagrams: null });
    const [diagErr, setDiagErr] = useState(false);
    const handleText = e => setData(p => ({ ...p, [e.target.name]: e.target.value }));
    const handleFile = name => e => { const f = e.target.files?.[0] || null; setFiles(p => ({ ...p, [name]: f })); if (name === 'architecture_diagram' && f) setDiagErr(false); };
    const submit = () => { if (!files.architecture_diagram) { setDiagErr(true); setStep(0); return; } const fd = new FormData(); Object.entries(data).forEach(([k, v]) => { if (v) fd.append(k, v); }); Object.entries(files).forEach(([k, v]) => { if (v instanceof File) fd.append(k, v); }); onSubmit(fd); };
    const textFields = ALL_FIELDS.filter(([, , type, s]) => s === step && type !== 'file');
    const pct = Math.round((step / (STEPS.length - 1)) * 100);

    return (
        <div>
            {/* Progress */}
            <div style={{ marginBottom: 28 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--t1)' }}>{STEPS[step].label}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t3)' }}>Step {step + 1} of {STEPS.length}</span>
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, fontWeight: 700, color: '#3b8ef0', background: 'rgba(59,142,240,0.14)', padding: '3px 10px', borderRadius: 6 }}>{pct}%</span>
                    </div>
                </div>
                <div style={{ height: 5, background: 'rgba(255,255,255,0.07)', borderRadius: 5, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${pct}%`, background: 'linear-gradient(90deg,#1454b8,#3b8ef0)', borderRadius: 5, transition: 'width 0.35s cubic-bezier(0.4,0,0.2,1)', boxShadow: '0 0 10px rgba(59,142,240,0.55)' }} />
                </div>
                {/* Step dots */}
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    {STEPS.map((s, i) => (
                        <button key={i} onClick={() => setStep(i)} title={s.label} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', padding: '2px 8px' }}>
                            <div style={{ width: 10, height: 10, borderRadius: '50%', background: i < step ? '#22c55e' : i === step ? '#3b8ef0' : 'rgba(255,255,255,0.14)', border: i === step ? '2px solid rgba(59,142,240,0.45)' : 'none', boxShadow: i === step ? '0 0 10px rgba(59,142,240,0.65)' : 'none', transition: 'all 0.2s' }} />
                        </button>
                    ))}
                </div>
            </div>

            {/* Step chips */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 24, overflowX: 'auto', paddingBottom: 4 }}>
                {STEPS.map((s, i) => {
                    const Icon = s.icon; const isA = i === step; const isDone = i < step;
                    return (
                        <button key={i} onClick={() => setStep(i)} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 9, fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap', flexShrink: 0, cursor: 'pointer', transition: 'all 0.18s', background: isA ? 'rgba(59,142,240,0.16)' : isDone ? 'rgba(34,197,94,0.08)' : 'rgba(255,255,255,0.04)', border: `1.5px solid ${isA ? 'rgba(59,142,240,0.55)' : isDone ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.1)'}`, color: isA ? '#93c5fd' : isDone ? '#86efac' : 'var(--t3)', boxShadow: isA ? '0 0 18px rgba(59,142,240,0.18)' : 'none', fontFamily: "'DM Sans',sans-serif" }}>
                            <Icon size={13} />{s.label}
                            {isDone && <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e', marginLeft: 2 }} />}
                        </button>
                    );
                })}
            </div>

            {/* Error alert */}
            {diagErr && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.35)', borderRadius: 10, marginBottom: 20, color: '#fca5a5', fontSize: 13, fontWeight: 600 }}>
                    <AlertCircle size={16} style={{ flexShrink: 0 }} />
                    Architecture Diagram is required — upload it in the "App & Architecture" step.
                </div>
            )}

            {/* Fields */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 18 }}>
                {textFields.map(([key, label, type, , options]) => (
                    <div key={key} style={{ gridColumn: type === 'textarea' ? '1 / -1' : undefined }}>
                        {type === 'textarea' && <FTextarea label={label} name={key} value={data[key]} onChange={handleText} />}
                        {type === 'select' && <FSelect label={label} name={key} value={data[key]} onChange={handleText} options={options} />}
                        {type === 'text' && <FInput label={label} name={key} value={data[key]} onChange={handleText} />}
                    </div>
                ))}
            </div>

            {/* Diagram uploads */}
            {step === 0 && (
                <div style={{ marginTop: 28 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 18 }}>
                        <div className="divider-blue" style={{ flex: 1 }} />
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 600, color: 'rgba(59,142,240,0.65)', letterSpacing: '0.12em', whiteSpace: 'nowrap' }}>ARCHITECTURE DIAGRAMS</span>
                        <div className="divider-blue" style={{ flex: 1 }} />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 14 }}>
                        <div style={{ gridColumn: '1 / -1' }}><FFile label="Architecture Diagram" name="architecture_diagram" file={files.architecture_diagram} onChange={handleFile('architecture_diagram')} required /></div>
                        {['High_level_architecture', 'Logical_architecture', 'Physical_architecture', 'Data_flow_diagrams'].map(k => (
                            <FFile key={k} label={k.replace(/_/g, ' ')} name={k} file={files[k]} onChange={handleFile(k)} />
                        ))}
                    </div>
                </div>
            )}

            {/* Footer */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 32, paddingTop: 20, borderTop: '1px solid var(--b1)' }}>
                <div style={{ display: 'flex', gap: 8 }}>
                    <Btn variant="ghost" onClick={onCancel}>Cancel</Btn>
                    {step > 0 && <Btn variant="secondary" onClick={() => setStep(s => s - 1)}><ArrowLeft size={14} />Back</Btn>}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontSize: 11, color: 'var(--t4)', fontFamily: "'JetBrains Mono',monospace" }}>
                        {step < STEPS.length - 1 ? `${STEPS.length - step - 1} step${STEPS.length - step - 1 > 1 ? 's' : ''} left` : 'Final step'}
                    </span>
                    {step < STEPS.length - 1
                        ? <Btn onClick={() => setStep(s => s + 1)}>Next Step <ChevronRight size={14} /></Btn>
                        : <Btn onClick={submit} loading={loading}><Save size={14} />{initial ? 'Update Assessment' : 'Create Assessment'}</Btn>
                    }
                </div>
            </div>
        </div>
    );
};

// ─── Dashboard ────────────────────────────────────────────────────────────────
const StatCard = ({ label, value, sub, icon: Icon, accent = '#3b8ef0', delay = 0 }) => (
    <div className={`card stat-card shimmer fade-up d${delay + 1}`} style={{ padding: '20px 22px' }}>
        <div style={{ position: 'absolute', top: 0, right: 0, width: 80, height: 80, borderRadius: '0 14px 0 80px', background: `${accent}07`, pointerEvents: 'none' }} />
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div>
                <p style={{ fontSize: 36, fontWeight: 800, color: 'var(--t1)', lineHeight: 1, margin: '0 0 7px', letterSpacing: '-0.02em', fontVariantNumeric: 'tabular-nums' }}>{value ?? '—'}</p>
                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--t2)', margin: '0 0 3px' }}>{label}</p>
                {sub && <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: accent, opacity: 0.85, margin: 0 }}>{sub}</p>}
            </div>
            <div style={{ padding: 10, borderRadius: 12, background: `${accent}16`, border: `1px solid ${accent}28` }}>
                <Icon size={20} color={accent} />
            </div>
        </div>
    </div>
);

const Dashboard = ({ stats, loading }) => {
    if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: '64px 0' }}><Spinner size="lg" /></div>;
    if (!stats) return <EmptyState icon={BarChart3} title="No statistics yet" subtitle="Create your first assessment to populate the dashboard" />;
    const { assessments: a = {}, vulnerabilities: v = {}, top_categories: cats = [] } = stats;
    return (
        <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 16 }}>
                <StatCard icon={Shield} label="Total Assessments" value={a.total} sub={`${a.completed ?? 0} completed`} accent="#3b8ef0" delay={0} />
                <StatCard icon={ShieldAlert} label="Findings" value={v.total} sub={`${v.open ?? 0} open`} accent="#ef4444" delay={1} />
                <StatCard icon={AlertTriangle} label="Critical / High" value={(v.critical ?? 0) + (v.high ?? 0)} sub="Need immediate attention" accent="#f97316" delay={2} />
                <StatCard icon={ShieldCheck} label="Fixed" value={v.fixed} sub="Resolved issues" accent="#22c55e" delay={3} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="card" style={{ padding: 20 }}>
                    <SectionLabel>Risk Distribution</SectionLabel>
                    {[{ label: 'High Risk', val: a.high_risk ?? 0, color: '#f87171', bg: 'rgba(239,68,68,0.1)' }, { label: 'Medium Risk', val: a.medium_risk ?? 0, color: '#fb923c', bg: 'rgba(249,115,22,0.1)' }, { label: 'Low Risk', val: a.low_risk ?? 0, color: '#4ade80', bg: 'rgba(34,197,94,0.1)' }].map(r => {
                        const p = a.total ? Math.round((r.val / a.total) * 100) : 0;
                        return (
                            <div key={r.label} style={{ marginBottom: 16 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 7 }}>
                                    <span style={{ fontSize: 13, color: 'var(--t2)', fontWeight: 600 }}>{r.label}</span>
                                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: r.color, fontWeight: 700 }}>{r.val} <span style={{ color: 'var(--t4)', fontWeight: 400 }}>({p}%)</span></span>
                                </div>
                                <div style={{ height: 6, background: 'rgba(255,255,255,0.07)', borderRadius: 4, overflow: 'hidden' }}>
                                    <div style={{ height: '100%', width: `${p}%`, background: r.color, borderRadius: 4, boxShadow: `0 0 8px ${r.color}55`, transition: 'width 0.65s ease' }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
                <div className="card" style={{ padding: 20 }}>
                    <SectionLabel>Top Finding Categories</SectionLabel>
                    {cats.length === 0
                        ? <p style={{ fontSize: 13, color: 'var(--t4)', textAlign: 'center', padding: '20px 0' }}>No data yet</p>
                        : cats.slice(0, 6).map((c, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: i < 5 ? '1px solid var(--b3)' : 'none' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)', width: 20, fontWeight: 700 }}>#{i + 1}</span>
                                    <span style={{ fontSize: 13, color: 'var(--t2)', fontWeight: 500 }}>{c.category_tag}</span>
                                </div>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, fontWeight: 700, color: '#3b8ef0', background: 'rgba(59,142,240,0.12)', padding: '2px 10px', borderRadius: 5 }}>{c.count}</span>
                            </div>
                        ))
                    }
                </div>
            </div>
        </div>
    );
};

// ─── Activity Log ─────────────────────────────────────────────────────────────
const ActivityLog = ({ entries, loading }) => {
    if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner size="lg" /></div>;
    if (!entries?.length) return <EmptyState icon={History} title="No activity yet" subtitle="Changes and events will appear here" />;
    return (
        <div style={{ paddingTop: 8 }}>
            {entries.map((e, i) => (
                <div key={e.id || i} style={{ display: 'flex', gap: 14 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#3b8ef0', boxShadow: '0 0 8px rgba(59,142,240,0.65)', marginTop: 4, flexShrink: 0 }} />
                        {i < entries.length - 1 && <div style={{ width: 1, flex: 1, background: 'linear-gradient(to bottom,rgba(59,142,240,0.28),transparent)', margin: '4px 0' }} />}
                    </div>
                    <div style={{ paddingBottom: 20, flex: 1 }}>
                        <div className="card" style={{ padding: '12px 16px' }}>
                            <p style={{ fontSize: 13, color: 'var(--t1)', fontWeight: 600, margin: '0 0 7px' }}>{e.change_reason || e.action || e.description || e.message || '—'}</p>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t4)' }}>{fmtDateTime(e.timestamp || e.created_at)}</span>
                                {e.changed_by && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t3)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 4 }}>by {e.changed_by}</span>}
                                {e.score_change != null && e.score_change !== 0 && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, fontWeight: 700, color: e.score_change > 0 ? '#86efac' : '#fca5a5' }}>{e.score_change > 0 ? '↑' : '↓'} {Math.abs(e.score_change)} pts</span>}
                            </div>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

// ─── Controls Panel ───────────────────────────────────────────────────────────
const CTRL_STATUS_OPTS = ['pending', 'implemented', 'verified', 'not_applicable'];

const ControlsPanel = ({ vulnId }) => {
    const [controls, setControls] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showAdd, setShowAdd] = useState(false);
    const [editId, setEditId] = useState(null);
    const [editData, setEditData] = useState({});
    const [histCtrl, setHistCtrl] = useState(null);
    const [histEntries, setHistEntries] = useState([]);
    const [histLoading, setHistLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const blank = { control_name: '', control_description: '', implementation_details: '', status: 'pending', risk_reduction_percentage: '', verification_notes: '', verified_by: '' };
    const [newCtrl, setNewCtrl] = useState(blank);
    const load = useCallback(async () => { setLoading(true); try { const d = await listControlsForVulnerability(vulnId); setControls(Array.isArray(d) ? d : d?.results || []); } catch { setControls([]); } setLoading(false); }, [vulnId]);
    useEffect(() => { load(); }, [load]);
    const handleCreate = async () => { if (!newCtrl.control_name.trim()) return; setSaving(true); try { await createControl(vulnId, newCtrl); setShowAdd(false); setNewCtrl(blank); load(); } catch (e) { alert(e.message); } setSaving(false); };
    const handleUpdate = async () => { setSaving(true); try { await updateControl(editId, editData); setEditId(null); load(); } catch (e) { alert(e.message); } setSaving(false); };
    const handleDelete = async id => { if (!window.confirm('Delete this control?')) return; try { await deleteControl(id); load(); } catch (e) { alert(e.message); } };
    const openHistory = async ctrl => { setHistCtrl(ctrl); setHistLoading(true); try { const d = await getControlUpdateHistory(ctrl.id); setHistEntries(Array.isArray(d) ? d : [d]); } catch { setHistEntries([]); } setHistLoading(false); };
    const CInput = ({ label, k, obj, setObj, type = 'text' }) => (
        <div>
            <label className="f-label" style={{ marginBottom: 6 }}><span className="f-label-bar" />{label}</label>
            {type === 'select'
                ? <div style={{ position: 'relative' }}><select className="ara-input" value={obj[k] || ''} onChange={e => setObj(p => ({ ...p, [k]: e.target.value }))} style={{ appearance: 'none', paddingRight: 34 }}>{CTRL_STATUS_OPTS.map(o => <option key={o} value={o}>{fmtStatus(o)}</option>)}</select><ChevronDown size={13} color="var(--t4)" style={{ position: 'absolute', right: 11, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} /></div>
                : <input className="ara-input" type="text" value={obj[k] || ''} onChange={e => setObj(p => ({ ...p, [k]: e.target.value }))} />
            }
        </div>
    );
    if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 16 }}><Spinner /></div>;
    return (
        <div style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <SectionLabel>Remediation Controls ({controls.length})</SectionLabel>
                {!showAdd && <Btn size="sm" variant="secondary" onClick={() => setShowAdd(true)}><Plus size={12} />Add Control</Btn>}
            </div>
            {showAdd && (
                <div style={{ background: 'rgba(59,142,240,0.07)', border: '1px solid rgba(59,142,240,0.22)', borderRadius: 12, padding: 16, marginBottom: 12 }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 12, marginBottom: 12 }}>
                        <CInput label="Control Name *" k="control_name" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Status" k="status" obj={newCtrl} setObj={setNewCtrl} type="select" />
                        <CInput label="Description" k="control_description" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Implementation Details" k="implementation_details" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Risk Reduction %" k="risk_reduction_percentage" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Verified By" k="verified_by" obj={newCtrl} setObj={setNewCtrl} />
                    </div>
                    <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}><Btn size="sm" variant="ghost" onClick={() => setShowAdd(false)}>Cancel</Btn><Btn size="sm" onClick={handleCreate} loading={saving}><Save size={12} />Save Control</Btn></div>
                </div>
            )}
            {controls.map(c => (
                <div key={c.id} className="ctrl-card" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--b3)', borderRadius: 10, padding: 12, marginBottom: 8 }}>
                    {editId === c.id ? (
                        <div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 10, marginBottom: 10 }}>
                                <CInput label="Control Name" k="control_name" obj={editData} setObj={setEditData} />
                                <CInput label="Status" k="status" obj={editData} setObj={setEditData} type="select" />
                                <CInput label="Description" k="control_description" obj={editData} setObj={setEditData} />
                                <CInput label="Implementation Details" k="implementation_details" obj={editData} setObj={setEditData} />
                            </div>
                            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}><Btn size="sm" variant="ghost" onClick={() => setEditId(null)}>Cancel</Btn><Btn size="sm" onClick={handleUpdate} loading={saving}><Save size={12} />Save</Btn></div>
                        </div>
                    ) : (
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                            <div style={{ flex: 1 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, flexWrap: 'wrap' }}>
                                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--t1)' }}>{c.control_name}</span>
                                    <StatusPill status={c.status} />
                                    {c.risk_reduction_percentage != null && <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", color: '#86efac', background: 'rgba(34,197,94,0.12)', padding: '2px 8px', borderRadius: 5, fontWeight: 700 }}>↓{c.risk_reduction_percentage}%</span>}
                                </div>
                                {c.control_description && <p style={{ fontSize: 12, color: 'var(--t3)', margin: 0 }}>{c.control_description}</p>}
                            </div>
                            <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                                {[{ I: Eye, fn: () => openHistory(c), d: false }, { I: Edit3, fn: () => { setEditId(c.id); setEditData({ ...c }); }, d: false }, { I: Trash2, fn: () => handleDelete(c.id), d: true }].map(({ I, fn, d }, idx) => (
                                    <button key={idx} onClick={fn} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 7, borderRadius: 7, color: d ? '#fca5a5' : 'var(--t3)', display: 'flex', transition: 'all 0.15s' }}
                                        onMouseEnter={e => e.currentTarget.style.background = d ? 'rgba(239,68,68,0.12)' : 'rgba(255,255,255,0.08)'}
                                        onMouseLeave={e => e.currentTarget.style.background = 'none'}>
                                        <I size={14} />
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            ))}
            {controls.length === 0 && !showAdd && <div style={{ textAlign: 'center', padding: '16px 0', color: 'var(--t4)', fontSize: 13, border: '1px dashed rgba(255,255,255,0.08)', borderRadius: 10 }}>No controls added yet</div>}
            <Modal open={!!histCtrl} onClose={() => setHistCtrl(null)} title={`History — ${histCtrl?.control_name}`}>
                {histLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner size="lg" /></div> : (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 10 }}>
                        {histEntries.map(e => Object.entries(e).filter(([k, v]) => v && k !== 'id').map(([k, v]) => (
                            <div key={k} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 10, padding: 12, border: '1px solid var(--b1)' }}>
                                <p style={{ fontSize: 10, color: 'var(--t4)', textTransform: 'capitalize', fontFamily: "'JetBrains Mono',monospace", marginBottom: 4 }}>{k.replace(/_/g, ' ')}</p>
                                <p style={{ fontSize: 13, color: 'var(--t1)', fontWeight: 500, wordBreak: 'break-words', margin: 0 }}>{String(v)}</p>
                            </div>
                        )))}
                    </div>
                )}
            </Modal>
        </div>
    );
};

// ─── Vulnerabilities ──────────────────────────────────────────────────────────
const VULN_STATUSES = ['open', 'in_progress', 'fixed'];

const VulnerabilitiesPanel = ({ assessmentId }) => {
    const [vulns, setVulns] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState(null);
    const [updatingId, setUpdatingId] = useState(null);
    const load = useCallback(async () => { setLoading(true); try { const d = await listVulnerabilities(assessmentId); setVulns(Array.isArray(d) ? d : d?.results || []); } catch { setVulns([]); } setLoading(false); }, [assessmentId]);
    useEffect(() => { load(); }, [load]);
    const handleStatus = async (vulnId, status) => { setUpdatingId(vulnId); try { const u = await updateVulnerabilityStatus(vulnId, { status }); setVulns(prev => prev.map(v => v.id === vulnId ? { ...v, ...u } : v)); } catch (e) { alert(e.message); } setUpdatingId(null); };
    const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
    const sortedVulns = [...vulns].sort((a, b) => {
        const aRank = SEVERITY_ORDER[(a.severity || '').toLowerCase()] ?? 99;
        const bRank = SEVERITY_ORDER[(b.severity || '').toLowerCase()] ?? 99;
        return aRank - bRank;
    });
    if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spinner size="lg" /></div>;
    if (!vulns.length) return <EmptyState icon={ShieldAlert} title="No Findings found" subtitle="Results will appear after analysis completes" />;
    return (
        <div>
            <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--t3)', marginBottom: 16 }}>
                <span style={{ color: '#3b8ef0', fontWeight: 700 }}>{vulns.length}</span> vulnerabilit{vulns.length === 1 ? 'y' : 'ies'} identified
            </p>
            {sortedVulns.map(v => {
                const r = riskMeta(v.severity); const isOpen = expanded === v.id; const sev = (v.severity || '').toLowerCase();
                return (
                    <div key={v.id} className={`vuln-row ${sev}`} style={{ background: isOpen ? 'rgba(255,255,255,0.025)' : 'rgba(255,255,255,0.015)', border: `1px solid ${isOpen ? 'var(--b1)' : 'var(--b3)'}`, borderRadius: 13, marginBottom: 10, overflow: 'hidden', transition: 'all 0.18s' }}>
                        <div style={{ padding: '14px 18px', display: 'flex', alignItems: 'flex-start', gap: 14, cursor: 'pointer' }} onClick={() => setExpanded(isOpen ? null : v.id)}>
                            <div style={{ width: 38, height: 38, borderRadius: 10, background: r.bg, border: `1px solid ${r.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                                <ShieldAlert size={17} color={r.text} />
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10, marginBottom: 7, flexWrap: 'wrap' }}>
                                    <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--t1)', margin: 0 }}>{v.control_title}</p>
                                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}><Badge label={v.severity} /><StatusPill status={v.status} /></div>
                                </div>
                                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                                    {v.category_tag && <span style={{ fontSize: 11, color: '#60a5fa', background: 'rgba(59,142,240,0.13)', padding: '2px 9px', borderRadius: 5, fontWeight: 700 }}>{v.category_tag}</span>}
                                    {v.cvss_score && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t3)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 5 }}>CVSS {v.cvss_score}</span>}
                                    {v.cwe_id && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t4)' }}>{v.cwe_id}</span>}
                                </div>
                                {v.control_description && !isOpen && <p style={{ fontSize: 12, color: 'var(--t3)', marginTop: 6, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical' }}>{v.control_description}</p>}
                            </div>
                            <div style={{ flexShrink: 0, marginTop: 2, color: 'var(--t4)' }}>{isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}</div>
                        </div>
                        {isOpen && (
                            <div style={{ borderTop: '1px solid var(--b3)', padding: '18px 18px 18px 70px' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 12, marginBottom: 16 }}>
                                    {v.control_description && <div style={{ gridColumn: '1 / -1', background: 'rgba(255,255,255,0.025)', border: '1px solid var(--b1)', borderRadius: 10, padding: 14 }}><SectionLabel>Description</SectionLabel><p style={{ fontSize: 13, color: 'var(--t2)', lineHeight: 1.65, margin: 0 }}>{v.control_description}</p></div>}
                                    {v.control_impact && <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.18)', borderRadius: 10, padding: 14 }}><SectionLabel>Impact</SectionLabel><p style={{ fontSize: 13, color: '#fca5a5', lineHeight: 1.6, margin: 0 }}>{v.control_impact}</p></div>}
                                    {v.control_recommendation && <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.18)', borderRadius: 10, padding: 14 }}><SectionLabel>Recommendation</SectionLabel><p style={{ fontSize: 13, color: '#86efac', lineHeight: 1.6, margin: 0 }}>{v.control_recommendation}</p></div>}
                                    {v.owasp_category && <div style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid var(--b1)', borderRadius: 10, padding: 14 }}><SectionLabel>OWASP Category</SectionLabel><p style={{ fontSize: 13, color: 'var(--t2)', margin: 0 }}>{v.owasp_category}</p></div>}
                                    {v.framework_mapping && <div style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid var(--b1)', borderRadius: 10, padding: 14 }}><SectionLabel>Framework Mapping</SectionLabel><p style={{ fontSize: 13, color: 'var(--t2)', margin: 0 }}>{v.framework_mapping}</p></div>}
                                </div>
                                <div style={{ display: 'flex', gap: 20, marginBottom: 16, fontSize: 12, fontFamily: "'JetBrains Mono',monospace", color: 'var(--t3)' }}>
                                    <span>Controls: <span style={{ color: 'var(--t1)', fontWeight: 700 }}>{v.remediation_count ?? 0}</span></span>
                                    <span>Remediated: <span style={{ color: v.is_remediated ? '#86efac' : '#fca5a5', fontWeight: 700 }}>{v.is_remediated ? 'Yes' : 'No'}</span></span>
                                </div>
                                <div style={{ marginBottom: 16 }}>
                                    <SectionLabel>Update Status</SectionLabel>
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                        {VULN_STATUSES.map(s => {
                                            const sm = statusMeta(s); const isA = v.status === s; return (
                                                <button key={s} onClick={() => handleStatus(v.id, s)} disabled={!!updatingId} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 16px', borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s', background: isA ? sm.bg : 'rgba(255,255,255,0.05)', border: `1.5px solid ${isA ? sm.border : 'rgba(255,255,255,0.1)'}`, color: isA ? sm.text : 'var(--t3)', fontFamily: "'DM Sans',sans-serif" }}>
                                                    {updatingId === v.id && !isA && <Spinner />}{fmtStatus(s)}
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                                <ControlsPanel vulnId={v.id} />
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

// ─── Assessment Detail ────────────────────────────────────────────────────────
const AssessmentDetail = ({ assessment, onBack, onDeleted, onUpdated }) => {
    const [details, setDetails] = useState(assessment);
    const [detailsLoading, setDL] = useState(true);
    const [tab, setTab] = useState('vulnerabilities');
    const [history, setHistory] = useState([]);
    const [histLoading, setHL] = useState(false);
    const [showEdit, setShowEdit] = useState(false);
    const [saving, setSaving] = useState(false);
    const [downloading, setDLing] = useState(false);
    const [deleting, setDeleting] = useState(false);
    useEffect(() => { (async () => { setDL(true); try { setDetails(await getAssessmentDetails(assessment.id)); } catch { } setDL(false); })(); }, [assessment.id]);
    const loadHistory = useCallback(async () => { setHL(true); try { const h = await getAssessmentHistory(assessment.id); setHistory(Array.isArray(h) ? h : h?.results || []); } catch { setHistory([]); } setHL(false); }, [assessment.id]);
    useEffect(() => { if (tab === 'history') loadHistory(); }, [tab, loadHistory]);
    const handleDownload = async () => { setDLing(true); try { await downloadExcelReport(assessment.id); } catch (e) { alert(e.message); } setDLing(false); };
    const handleDelete = async () => { if (!window.confirm('Permanently delete this assessment and all its data?')) return; setDeleting(true); try { await deleteAssessment(assessment.id); onDeleted(assessment.id); } catch (e) { alert(e.message); setDeleting(false); } };
    const handleUpdate = async fd => { setSaving(true); try { const u = await updateAssessment(assessment.id, fd); setDetails(u); setShowEdit(false); onUpdated(u); } catch (e) { alert(e.message); } setSaving(false); };
    const TABS = [{ key: 'vulnerabilities', label: 'Findings', icon: ShieldAlert }, { key: 'history', label: 'Activity Log', icon: Activity }, { key: 'details', label: 'All Details', icon: Info }];
    const score = details?.overall_risk_score;
    const scoreColor = score >= 70 ? '#f87171' : score >= 40 ? '#fb923c' : '#86efac';
    return (
        <div>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                    <button onClick={onBack} style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid var(--b1)', borderRadius: 10, padding: '9px 14px', cursor: 'pointer', color: 'var(--t2)', display: 'flex', alignItems: 'center', gap: 7, fontSize: 13, fontWeight: 700, transition: 'all 0.15s', marginTop: 4, fontFamily: "'DM Sans',sans-serif" }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(59,142,240,0.12)'; e.currentTarget.style.color = '#93c5fd'; e.currentTarget.style.borderColor = 'rgba(59,142,240,0.35)'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--t2)'; e.currentTarget.style.borderColor = 'var(--b1)'; }}>
                        <ArrowLeft size={14} /> Dashboard
                    </button>
                    <div>
                        <h2 style={{ fontSize: 22, fontWeight: 800, color: 'var(--t1)', margin: '0 0 8px', lineHeight: 1.2, letterSpacing: '-0.02em' }}>{details?.application_purpose || details?.application_type || 'Assessment'}</h2>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <StatusPill status={details?.status} />
                            {score != null && <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: `${scoreColor}14`, border: `1px solid ${scoreColor}38`, padding: '4px 12px', borderRadius: 7 }}><Zap size={12} color={scoreColor} /><span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: scoreColor, fontWeight: 700 }}>Risk Score: {score}</span></div>}
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--t4)' }}>{fmtDate(details?.created_at)}</span>
                        </div>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    <Btn size="sm" variant="success" onClick={handleDownload} loading={downloading}><Download size={13} />Export Excel</Btn>
                    <Btn size="sm" variant="secondary" onClick={() => setShowEdit(true)}><Edit3 size={13} />Edit</Btn>
                    <Btn size="sm" variant="danger" onClick={handleDelete} loading={deleting}><Trash2 size={13} />Delete</Btn>
                </div>
            </div>

            {/* Quick stats */}
            {detailsLoading
                ? <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}><Spinner size="lg" /></div>
                : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 24 }}>
                    {[{ label: 'Total Vulns', value: details?.vulnerability_count ?? '—', color: 'var(--t1)' }, { label: 'Critical', value: details?.critical_count ?? '—', color: '#fca5a5' }, { label: 'High', value: details?.high_count ?? '—', color: '#fdba74' }, { label: 'App Type', value: details?.application_type || '—', color: '#93c5fd' }].map(item => (
                        <div key={item.label} className="card" style={{ padding: '16px 18px' }}>
                            <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{item.label}</p>
                            <p style={{ fontSize: 22, fontWeight: 800, color: item.color, margin: 0, lineHeight: 1, letterSpacing: '-0.02em' }}>{item.value}</p>
                        </div>
                    ))}
                </div>
            }

            {/* Tab bar */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--b1)', marginBottom: 24, gap: 4 }}>
                {TABS.map(t => {
                    const Icon = t.icon; const isA = tab === t.key; return (
                        <button key={t.key} onClick={() => setTab(t.key)} className={`d-tab${isA ? ' active' : ''}`} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '10px 18px', fontSize: 13, fontWeight: 700, background: isA ? 'rgba(59,142,240,0.09)' : 'transparent', border: 'none', borderBottom: `2px solid ${isA ? 'var(--accent)' : 'transparent'}`, color: isA ? 'var(--accent)' : 'var(--t3)', transition: 'all 0.15s', borderRadius: '8px 8px 0 0', fontFamily: "'DM Sans',sans-serif", cursor: 'pointer' }}><Icon size={15} />{t.label}</button>
                    );
                })}
            </div>

            {tab === 'vulnerabilities' && <VulnerabilitiesPanel assessmentId={assessment.id} />}
            {tab === 'history' && <ActivityLog entries={history} loading={histLoading} />}
            {tab === 'details' && details && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
                    {Object.entries(details).filter(([k, v]) => !['id', 'vulnerable_components'].includes(k) && v != null && v !== '').map(([k, v]) => (
                        <div key={k} className="card" style={{ padding: '12px 14px' }}>
                            <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 5px' }}>{k.replace(/_/g, ' ')}</p>
                            <p style={{ fontSize: 13, color: 'var(--t2)', fontWeight: 500, wordBreak: 'break-words', margin: 0 }}>{typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v)}</p>
                        </div>
                    ))}
                </div>
            )}

            <Modal open={showEdit} onClose={() => setShowEdit(false)} title="Update Assessment" wide>
                <AssessmentForm initial={details} onSubmit={handleUpdate} onCancel={() => setShowEdit(false)} loading={saving} />
            </Modal>
        </div>
    );
};

// ─── Sidebar List ─────────────────────────────────────────────────────────────
const AssessmentListPanel = ({ assessments, selected, onSelect, onDeleted, search }) => {
    const [deleting, setDeleting] = useState(null);
    const handleDelete = async (e, id) => { e.stopPropagation(); if (!window.confirm('Delete this assessment?')) return; setDeleting(id); try { await deleteAssessment(id); onDeleted(id); } catch (err) { alert(err.message); } setDeleting(null); };
    const filtered = search ? assessments.filter(a => (a.application_purpose || '').toLowerCase().includes(search.toLowerCase())) : assessments;
    if (!filtered.length) return <EmptyState icon={ClipboardList} title={search ? 'No matches' : 'No assessments'} subtitle={search ? 'Try a different search' : 'Click + New Assessment to start'} />;
    return (
        <div>
            {filtered.map(a => {
                const isSel = selected?.id === a.id;
                const dotColor = a.status === 'completed' ? '#4ade80' : a.status === 'failed' ? '#f87171' : '#3b8ef0';
                return (
                    <div key={a.id} onClick={() => onSelect(a)} className={`s-item${isSel ? ' active' : ''}`} style={{ padding: '11px 12px', marginBottom: 4, position: 'relative' }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 6 }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
                                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: dotColor, boxShadow: `0 0 7px ${dotColor}80`, flexShrink: 0 }} />
                                    <p style={{ fontSize: 13, fontWeight: 700, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', margin: 0 }}>
                                        {a.application_purpose?.slice(0, 38) || 'Untitled Assessment'}
                                    </p>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: 14, flexWrap: 'wrap', marginBottom: 4 }}>
                                    <StatusPill status={a.status} />
                                    {a.overall_risk_score != null && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t3)' }}>Score <span style={{ color: 'var(--t2)', fontWeight: 700 }}>{a.overall_risk_score}</span></span>}
                                </div>
                                <div style={{ display: 'flex', gap: 8, paddingLeft: 14 }}>
                                    {a.critical_count > 0 && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: '#fca5a5', fontWeight: 700 }}>{a.critical_count} critical</span>}
                                    {a.vulnerability_count > 0 && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)' }}>{a.vulnerability_count} vulns</span>}
                                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)' }}>{fmtDate(a.created_at)}</span>
                                </div>
                            </div>
                            <button onClick={e => handleDelete(e, a.id)} disabled={deleting === a.id} className="s-del" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--t4)', padding: 5, display: 'flex', borderRadius: 6, transition: 'all 0.15s' }}
                                onMouseEnter={e => { e.currentTarget.style.color = '#fca5a5'; e.currentTarget.style.background = 'rgba(239,68,68,0.1)'; }}
                                onMouseLeave={e => { e.currentTarget.style.color = 'var(--t4)'; e.currentTarget.style.background = 'none'; }}>
                                {deleting === a.id ? <Spinner /> : <Trash2 size={13} />}
                            </button>
                        </div>
                    </div>
                );
            })}
        </div>
    );
};

// ─── Main Page ────────────────────────────────────────────────────────────────
const ArchitectureAssessmentPage = () => {
    const [view, setView] = useState('dashboard');
    const [assessments, setAssessments] = useState([]);
    const [aLoading, setALoading] = useState(true);
    const [stats, setStats] = useState(null);
    const [sLoading, setSLoading] = useState(true);
    const [selected, setSelected] = useState(null);
    const [creating, setCreating] = useState(false);
    const [sideSearch, setSideSearch] = useState('');

    const load = useCallback(async () => { setALoading(true); setSLoading(true); const [a, s] = await Promise.allSettled([listAssessments(), getStatistics()]); if (a.status === 'fulfilled') setAssessments(Array.isArray(a.value) ? a.value : a.value?.results || []); if (s.status === 'fulfilled') setStats(s.value); setALoading(false); setSLoading(false); }, []);
    useEffect(() => { load(); }, [load]);

    const handleCreate = async fd => { setCreating(true); try { const n = await createAssessment(fd); setAssessments(p => [n, ...p]); setView('dashboard'); load(); } catch (e) { alert(e.message); } setCreating(false); };
    const handleDeleted = id => { setAssessments(p => p.filter(a => a.id !== id)); if (selected?.id === id) { setSelected(null); setView('dashboard'); } load(); };
    const handleUpdated = u => setAssessments(p => p.map(a => a.id === u.id ? u : a));
    const selectAssessment = a => { setSelected(a); setView('detail'); };

    return (
        <>
            <GlobalStyles />
            <div className="ara-root">
                <div className="ara-bg" />
                <div className="ara-grid" />
                <div className="ara-orb ara-orb-1" />
                <div className="ara-orb ara-orb-2" />

                {/* ════════════════════ NAVBAR ════════════════════ */}
                <header style={{ position: 'sticky', top: 0, zIndex: 40, background: 'rgba(8,14,26,0.96)', backdropFilter: 'blur(20px)' }} className="nav-glow">
                    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '0 24px', height: 58, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        {/* Logo + breadcrumb */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexShrink: 0 }}>
                                <div style={{ width: 34, height: 34, borderRadius: 10, background: 'linear-gradient(135deg,rgba(20,84,184,0.32),rgba(59,142,240,0.22))', border: '1px solid rgba(59,142,240,0.38)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 16px rgba(59,142,240,0.2)' }}>
                                    <Shield size={17} color="#3b8ef0" />
                                </div>
                                <div>
                                    <p style={{ fontSize: 14, fontWeight: 800, color: 'var(--t1)', margin: 0, lineHeight: 1, letterSpacing: '-0.01em' }}>ARIA</p>
                                    <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(59,142,240,0.6)', margin: 0, letterSpacing: '0.12em' }}>RISK PLATFORM</p>
                                </div>
                            </div>
                            <div style={{ width: 1, height: 24, background: 'var(--b1)', flexShrink: 0 }} />
                            <Breadcrumb view={view} assessmentName={selected?.application_purpose?.slice(0, 28) || selected?.application_type} onDashboard={() => setView('dashboard')} />
                        </div>

                        {/* Right actions */}
                        {/* <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <button onClick={load} title="Refresh" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--b1)', borderRadius: 8, padding: 9, cursor: 'pointer', color: 'var(--t3)', display: 'flex', transition: 'all 0.15s' }}
                                onMouseEnter={e => { e.currentTarget.style.color = '#3b8ef0'; e.currentTarget.style.background = 'rgba(59,142,240,0.08)'; }}
                                onMouseLeave={e => { e.currentTarget.style.color = 'var(--t3)'; e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}>
                                <RefreshCw size={14} />
                            </button>
                            {view === 'dashboard' && <Btn size="sm" onClick={() => setView('create')}><Plus size={13} />New Assessment</Btn>}
                            {(view === 'create' || view === 'detail') && <Btn size="sm" variant="secondary" onClick={() => setView('dashboard')}><ArrowLeft size={13} />Dashboard</Btn>}
                        </div> */}
                    </div>
                </header>

                {/* ════════════════════ MAIN ════════════════════ */}
                <main style={{ maxWidth: 1440, margin: '0 auto', padding: '28px 24px 72px', position: 'relative', zIndex: 1 }}>

                    {/* ── CREATE ── */}
                    {view === 'create' && (
                        <div className="fade-up">
                            <div style={{ marginBottom: 24 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                    <div style={{ width: 18, height: 3, background: 'linear-gradient(90deg,#1e6fd9,#3b8ef0)', borderRadius: 2 }} />
                                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(59,142,240,0.65)', letterSpacing: '0.14em', textTransform: 'uppercase' }}>New Assessment</span>
                                </div>
                                <h1 style={{ fontSize: 30, fontWeight: 800, color: 'var(--t1)', margin: '0 0 4px', letterSpacing: '-0.02em' }}>Create Assessment</h1>
                                <p style={{ color: 'var(--t3)', fontSize: 13, margin: 0 }}>Note: Fill out the 5-step form below. Architecture Diagram is required.</p>
                            </div>
                            <div className="card2" style={{ padding: 32, boxShadow: '0 0 0 1px rgba(59,142,240,0.1),0 20px 50px rgba(0,0,0,0.5)' }}>
                                <AssessmentForm onSubmit={handleCreate} onCancel={() => setView('dashboard')} loading={creating} />
                            </div>
                        </div>
                    )}

                    {/* ── DETAIL ── */}
                    {view === 'detail' && selected && (
                        <div className="fade-up">
                            <div className="card2" style={{ padding: 32 }}>
                                <AssessmentDetail assessment={selected} onBack={() => setView('dashboard')} onDeleted={handleDeleted} onUpdated={handleUpdated} />
                            </div>
                        </div>
                    )}

                    {/* ── DASHBOARD ── */}
                    {view === 'dashboard' && (
                        <div style={{ display: 'flex', gap: 20 }}>

                            {/* Sidebar */}
                            <div style={{ width: 296, flexShrink: 0 }}>
                                <div className="card" style={{ overflow: 'hidden', position: 'sticky', top: 78 }}>
                                    {/* Header */}
                                    <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--b3)', background: 'rgba(59,142,240,0.04)' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <Clock size={14} color="rgba(59,142,240,0.75)" />
                                                <span style={{ fontSize: 14, fontWeight: 800, color: 'var(--t1)' }}>Assessments</span>
                                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: '#3b8ef0', background: 'rgba(59,142,240,0.15)', padding: '2px 8px', borderRadius: 5, fontWeight: 700 }}>{assessments.length}</span>
                                            </div>
                                            {aLoading ? <Spinner /> : (
                                                <button onClick={load} title="Refresh" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--t4)', display: 'flex', padding: 3, borderRadius: 5, transition: 'color 0.15s' }}
                                                    onMouseEnter={e => e.currentTarget.style.color = '#3b8ef0'}
                                                    onMouseLeave={e => e.currentTarget.style.color = 'var(--t4)'}>
                                                    <RefreshCw size={12} />
                                                </button>
                                            )}
                                        </div>
                                        {/* Search */}
                                        <div style={{ position: 'relative' }}>
                                            <Search size={12} color="var(--t4)" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                                            <input className="search-input" placeholder="Search assessments…" value={sideSearch} onChange={e => setSideSearch(e.target.value)} />
                                        </div>
                                    </div>
                                    {/* New shortcut */}
                                    <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--b3)' }}>
                                        <button onClick={() => setView('create')} style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: '9px 0', background: 'rgba(59,142,240,0.1)', border: '1.5px dashed rgba(59,142,240,0.32)', borderRadius: 9, cursor: 'pointer', color: '#60a5fa', fontSize: 13, fontWeight: 700, fontFamily: "'DM Sans',sans-serif", transition: 'all 0.15s' }}
                                            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(59,142,240,0.17)'; e.currentTarget.style.borderColor = 'rgba(59,142,240,0.55)'; }}
                                            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(59,142,240,0.1)'; e.currentTarget.style.borderColor = 'rgba(59,142,240,0.32)'; }}>
                                            <Plus size={15} /> New Assessment
                                        </button>
                                    </div>
                                    {/* List */}
                                    <div style={{ padding: '8px 10px', maxHeight: 'calc(100vh - 330px)', overflowY: 'auto' }}>
                                        <AssessmentListPanel assessments={assessments} selected={selected} onSelect={selectAssessment} onDeleted={handleDeleted} search={sideSearch} />
                                    </div>
                                </div>
                            </div>

                            {/* Right panel */}
                            <div style={{ flex: 1, minWidth: 0 }}>
                                {/* Hero */}
                                <div className="fade-up" style={{ marginBottom: 24 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                        <div style={{ width: 18, height: 3, background: 'linear-gradient(90deg,#1e6fd9,#3b8ef0)', borderRadius: 2 }} />
                                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(59,142,240,0.65)', letterSpacing: '0.14em', textTransform: 'uppercase' }}>Security Intelligence</span>
                                    </div>
                                    <h1 style={{ fontSize: 34, fontWeight: 800, color: 'var(--t1)', margin: '0 0 4px', lineHeight: 1.1, letterSpacing: '-0.025em' }}>
                                        Architecture Risk Assessment Dashboard{' '}
                                        {/* <span style={{ background: 'linear-gradient(135deg,#60a5fa,#93c5fd)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Dashboard</span> */}
                                    </h1>
                                    <p style={{ color: 'var(--t3)', fontSize: 13, margin: 0 }}>AI-powered Secure Architecture Review and Security Posture Analysis</p>
                                </div>

                                {/* Overview */}
                                <div className="card fade-up d1" style={{ padding: '22px 24px', marginBottom: 16 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                            <div style={{ padding: 8, borderRadius: 10, background: 'rgba(59,142,240,0.12)', border: '1px solid rgba(59,142,240,0.22)' }}><BarChart3 size={16} color="#3b8ef0" /></div>
                                            <span style={{ fontSize: 15, fontWeight: 800, color: 'var(--t1)' }}>Security Overview</span>
                                        </div>
                                        {sLoading && <Spinner />}
                                    </div>
                                    <Dashboard stats={stats} loading={sLoading} />
                                </div>

                                {/* Latest preview */}
                                {assessments.length > 0 && (
                                    <div className="card fade-up d2" style={{ padding: '20px 24px' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                                <div style={{ padding: 8, borderRadius: 10, background: 'rgba(59,142,240,0.1)', border: '1px solid rgba(59,142,240,0.2)' }}><Eye size={16} color="#60a5fa" /></div>
                                                <div>
                                                    <span style={{ fontSize: 14, fontWeight: 800, color: 'var(--t1)', display: 'block' }}>Latest Assessment</span>
                                                    <span style={{ fontSize: 11, color: 'var(--t4)', fontFamily: "'JetBrains Mono',monospace" }}>{fmtDate(assessments[0].created_at)}</span>
                                                </div>
                                            </div>
                                            <Btn size="sm" variant="secondary" onClick={() => selectAssessment(assessments[0])}>Open Details <ChevronRight size={13} /></Btn>
                                        </div>
                                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
                                            {[{ label: 'Application', value: assessments[0].application_purpose?.slice(0, 42) || '—' }, { label: 'Status', value: <StatusPill status={assessments[0].status} /> }, { label: 'Risk Score', value: assessments[0].overall_risk_score ?? '—' }, { label: 'Findings', value: assessments[0].vulnerability_count ?? '—' }].map(item => (
                                                <div key={item.label} style={{ background: 'var(--bg-base)', border: '1px solid var(--b3)', borderRadius: 12, padding: '14px 16px' }}>
                                                    <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--t4)', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{item.label}</p>
                                                    <div style={{ fontSize: 14, color: 'var(--t1)', fontWeight: 700 }}>{item.value}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </>
    );
};

export default ArchitectureAssessmentPage;