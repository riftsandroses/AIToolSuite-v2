import React, { useState, useEffect, useCallback } from 'react';
import {
    Shield, BarChart3, Clock, Plus, Trash2, Edit3, Download,
    ChevronRight, AlertTriangle, RefreshCw, ArrowLeft, Eye,
    FileText, Lock, Server, X, ChevronDown, ChevronUp, History,
    ClipboardList, ShieldAlert, ShieldCheck, Info, Save,
    Layers, Upload, Network, Settings, AlertCircle,
} from 'lucide-react';

import {
    createAssessment, listAssessments, getAssessmentDetails,
    updateAssessment, deleteAssessment, downloadExcelReport,
    getAssessmentHistory, getStatistics,
    listVulnerabilities, updateVulnerabilityStatus,
    listControlsForVulnerability, createControl, updateControl,
    getControlUpdateHistory, deleteControl,
} from './api';

// ── Helpers ───────────────────────────────────────────────────────────────────
const fmtDate = (d) =>
    d ? new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—';

const fmtDateTime = (d) =>
    d ? new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';

const riskColor = (level) => {
    const l = (level || '').toLowerCase();
    if (l === 'critical') return { bg: 'bg-red-600/20', text: 'text-red-400', border: 'border-red-500/30' };
    if (l === 'high') return { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' };
    if (l === 'medium') return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' };
    if (l === 'low') return { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' };
    return { bg: 'bg-slate-500/20', text: 'text-slate-400', border: 'border-slate-500/30' };
};

const statusBadge = (s) => {
    const st = (s || '').toLowerCase();
    if (st === 'open') return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (st === 'in_progress') return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    if (st === 'fixed') return 'bg-green-500/20 text-green-400 border-green-500/30';
    if (st === 'completed') return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    if (st === 'verified') return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    if (st === 'implemented') return 'bg-teal-500/20 text-teal-400 border-teal-500/30';
    return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
};

// ── All create-assessment fields (from Postman) ───────────────────────────────
const STEPS = [
    { label: 'Business Context', icon: FileText },
    { label: 'Application & Arch', icon: Server },
    { label: 'Infrastructure', icon: Network },
    { label: 'Security Controls', icon: Lock },
    { label: 'Operations & Risk', icon: Settings },
];

// [key, label, type, step, options?]  type: text|textarea|select|file
const ALL_FIELDS = [
    // Step 0 — Business Context
    ['application_purpose', 'Application Purpose', 'textarea', 0],
    ['business_objectives', 'Business Objectives', 'textarea', 0],
    ['business_criticality', 'Business Criticality', 'select', 0, ['Low', 'Medium', 'High', 'Critical']],
    ['impact_of_failure', 'Impact of Failure', 'textarea', 0],
    ['supported_business_processes', 'Supported Business Processes', 'text', 0],
    ['data_sensitivity', 'Data Sensitivity', 'select', 0, ['Public', 'Internal', 'Confidential', 'Highly sensitive financial data', 'Restricted']],
    ['data_classification_levels', 'Data Classification Levels', 'text', 0],
    ['regulatory_requirements', 'Regulatory Requirements', 'text', 0],
    ['compliance_requirements', 'Compliance Requirements', 'text', 0],
    ['stakeholders', 'Stakeholders', 'text', 0],
    ['system_owners', 'System Owners', 'text', 0],
    ['risk_tolerance', 'Risk Tolerance', 'select', 0, ['Low', 'Medium', 'High']],
    ['risk_acceptance_criteria', 'Risk Acceptance Criteria', 'text', 0],
    // Step 1 — Application & Architecture
    ['application_type', 'Application Type', 'select', 1, ['Web application', 'Mobile application', 'Desktop application', 'API/Backend Service', 'Hybrid']],
    ['usage_model', 'Usage Model', 'text', 1],
    ['functional_overview', 'Functional Overview', 'textarea', 1],
    ['major_modules', 'Major Modules', 'text', 1],
    ['user_roles', 'User Roles', 'text', 1],
    ['access_types', 'Access Types', 'text', 1],
    ['expected_traffic', 'Expected Traffic', 'text', 1],
    ['load_patterns', 'Load Patterns', 'text', 1],
    ['deployment_model', 'Deployment Model', 'select', 1, ['Cloud hosted', 'On-premise', 'Hybrid', 'SaaS']],
    ['programming_languages', 'Programming Languages', 'text', 1],
    ['frameworks_versions', 'Frameworks & Versions', 'text', 1],
    ['libraries_packages', 'Libraries & Packages', 'text', 1],
    ['runtime_environments', 'Runtime Environments', 'text', 1],
    ['databases', 'Databases', 'text', 1],
    ['storage_systems', 'Storage Systems', 'text', 1],
    ['middleware_components', 'Middleware Components', 'text', 1],
    ['message_queues', 'Message Queues', 'text', 1],
    ['api_gateways', 'API Gateways', 'text', 1],
    ['web_servers', 'Web Servers', 'text', 1],
    ['application_servers', 'Application Servers', 'text', 1],
    ['containerization_platforms', 'Containerization Platforms', 'text', 1],
    ['orchestration_platforms', 'Orchestration Platforms', 'text', 1],
    ['trust_boundaries', 'Trust Boundaries', 'text', 1],
    ['component_interaction', 'Component Interaction', 'text', 1],
    ['design_patterns', 'Design Patterns', 'text', 1],
    // Step 2 — Infrastructure
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
    // Step 3 — Security Controls
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
    // Step 4 — Operations & Risk
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
    ['known_vulnerabilities', 'Known Vulnerabilities', 'textarea', 4],
    ['accepted_risks', 'Accepted Risks', 'text', 4],
    ['architecture_assumptions', 'Architecture Assumptions', 'text', 4],
    ['design_constraints', 'Design Constraints', 'text', 4],
    ['technical_debt_areas', 'Technical Debt Areas', 'textarea', 4],
];

// ── Shared UI ─────────────────────────────────────────────────────────────────
const Spinner = ({ size = 'sm' }) => (
    <div className={`animate-spin rounded-full border-2 border-slate-600 border-t-blue-400 flex-shrink-0 ${size === 'sm' ? 'w-4 h-4' : 'w-8 h-8'}`} />
);

const Badge = ({ label, className = '' }) => {
    const c = riskColor(label);
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${c.bg} ${c.text} ${c.border} ${className}`}>
            {label}
        </span>
    );
};

const StatusPill = ({ status }) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${statusBadge(status)}`}>
        {(status || '—').replace(/_/g, ' ')}
    </span>
);

const Modal = ({ open, onClose, title, children, wide = false }) => {
    if (!open) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
            <div className={`relative bg-[#161b22] border border-[#2d3748] rounded-2xl shadow-2xl flex flex-col max-h-[90vh] ${wide ? 'w-full max-w-5xl' : 'w-full max-w-lg'}`}>
                <div className="flex items-center justify-between px-6 py-4 border-b border-[#2d3748] flex-shrink-0">
                    <h2 className="text-base font-bold text-white">{title}</h2>
                    <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>
                <div className="overflow-y-auto p-6 flex-1">{children}</div>
            </div>
        </div>
    );
};

const FInput = ({ label, name, value, onChange, placeholder, required, className = '' }) => (
    <div className={className}>
        {label && <label className="block text-xs font-medium text-blue-400 mb-1.5">{label}{required && <span className="text-red-400 ml-0.5">*</span>}</label>}
        <input type="text" name={name} value={value || ''} onChange={onChange} placeholder={placeholder || label} required={required}
            className="w-full px-3 py-2 bg-[#0d1117] border border-[#2d3748] rounded-lg text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm" />
    </div>
);

const FTextarea = ({ label, name, value, onChange, rows = 3, className = '' }) => (
    <div className={className}>
        {label && <label className="block text-xs font-medium text-blue-400 mb-1.5">{label}</label>}
        <textarea name={name} value={value || ''} onChange={onChange} rows={rows}
            className="w-full px-3 py-2 bg-[#0d1117] border border-[#2d3748] rounded-lg text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm resize-none" />
    </div>
);

const FSelect = ({ label, name, value, onChange, options, className = '' }) => (
    <div className={className}>
        {label && <label className="block text-xs font-medium text-blue-400 mb-1.5">{label}</label>}
        <div className="relative">
            <select name={name} value={value || ''} onChange={onChange}
                className="w-full appearance-none px-3 py-2 bg-[#0d1117] border border-[#2d3748] rounded-lg text-white focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm cursor-pointer">
                <option value="">— Select —</option>
                {options.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
        </div>
    </div>
);

const FFile = ({ label, name, file, onChange, required, className = '' }) => (
    <div className={className}>
        <label className="block text-xs font-medium text-blue-400 mb-1.5">
            {label}{required && <span className="text-red-400 ml-0.5">*</span>}
        </label>
        <div className={`flex items-center gap-3 px-3 py-2 rounded-lg border ${required && !file ? 'border-red-500/40 bg-red-500/5' : 'border-[#2d3748] bg-[#0d1117]'}`}>
            <Upload className="w-4 h-4 text-slate-400 flex-shrink-0" />
            <label className="flex-1 cursor-pointer">
                <span className="text-sm text-slate-400 hover:text-white transition-colors">
                    {file ? file.name : `Choose file${required ? ' (required)' : ' (optional)'}`}
                </span>
                <input type="file" name={name} accept="image/*,.pdf,.svg" onChange={onChange} className="hidden" />
            </label>
            {file && (
                <button type="button" onClick={() => onChange({ target: { files: [] } })} className="text-slate-500 hover:text-red-400">
                    <X className="w-3.5 h-3.5" />
                </button>
            )}
        </div>
    </div>
);

const Btn = ({ children, onClick, variant = 'primary', size = 'md', disabled, loading, className = '', type = 'button' }) => {
    const base = 'inline-flex items-center gap-2 font-medium rounded-lg transition-all focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed';
    const sizes = { sm: 'px-3 py-1.5 text-xs', md: 'px-4 py-2.5 text-sm', lg: 'px-6 py-3 text-sm' };
    const variants = {
        primary: 'bg-blue-600 hover:bg-blue-500 text-white',
        secondary: 'bg-[#1c2230] border border-[#2d3748] hover:border-[#4a5568] text-slate-300 hover:text-white',
        danger: 'bg-red-600/10 border border-red-500/30 hover:bg-red-600/20 text-red-400',
        ghost: 'text-slate-400 hover:text-white hover:bg-slate-700/50',
        success: 'bg-green-600/10 border border-green-500/30 hover:bg-green-600/20 text-green-400',
    };
    return (
        <button type={type} onClick={onClick} disabled={disabled || loading}
            className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}>
            {loading && <Spinner />}{children}
        </button>
    );
};

const EmptyState = ({ icon: Icon = FileText, title, subtitle }) => (
    <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="p-4 rounded-full bg-slate-800/50 mb-4"><Icon className="w-7 h-7 text-slate-500" /></div>
        <p className="text-slate-300 font-medium text-sm">{title}</p>
        {subtitle && <p className="text-slate-500 text-xs mt-1">{subtitle}</p>}
    </div>
);

// ── Assessment Form ───────────────────────────────────────────────────────────
const AssessmentForm = ({ initial, onSubmit, onCancel, loading }) => {
    const [step, setStep] = useState(0);
    const [data, setData] = useState(() => {
        const d = {};
        ALL_FIELDS.forEach(([key]) => { d[key] = initial?.[key] ?? ''; });
        return d;
    });
    const [files, setFiles] = useState({
        architecture_diagram: null, // REQUIRED
        high_level_architecture: null,
        logical_architecture: null,
        physical_architecture: null,
        data_flow_diagrams: null,
    });
    const [diagErr, setDiagErr] = useState(false);

    const handleText = (e) => setData(p => ({ ...p, [e.target.name]: e.target.value }));
    const handleFile = (name) => (e) => {
        const file = e.target.files?.[0] || null;
        setFiles(p => ({ ...p, [name]: file }));
        if (name === 'architecture_diagram' && file) setDiagErr(false);
    };

    const submit = () => {
        if (!files.architecture_diagram) { setDiagErr(true); setStep(1); return; }
        const fd = new FormData();
        Object.entries(data).forEach(([k, v]) => { if (v) fd.append(k, v); });
        Object.entries(files).forEach(([k, v]) => { if (v instanceof File) fd.append(k, v); });
        onSubmit(fd);
    };

    const textFields = ALL_FIELDS.filter(([, , type, s]) => s === step && type !== 'file');
    const fileFields = ALL_FIELDS.filter(([, , type, s]) => s === step && type === 'file');

    return (
        <div>
            {/* Step tabs */}
            <div className="flex items-center gap-1 mb-6 overflow-x-auto pb-1">
                {STEPS.map((s, i) => {
                    const Icon = s.icon;
                    return (
                        <button key={i} onClick={() => setStep(i)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all flex-shrink-0
                ${step === i ? 'bg-blue-600 text-white' : i < step ? 'bg-green-600/20 text-green-400 border border-green-500/30' : 'bg-[#0d1117] text-slate-400 border border-[#2d3748] hover:text-white'}`}>
                            <Icon className="w-3.5 h-3.5" />{s.label}
                        </button>
                    );
                })}
            </div>

            {diagErr && (
                <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    Architecture Diagram is required — please upload it on the "Application &amp; Arch" step.
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {textFields.map(([key, label, type, , options]) => {
                    if (type === 'textarea') return <FTextarea key={key} label={label} name={key} value={data[key]} onChange={handleText} className="md:col-span-2" />;
                    if (type === 'select') return <FSelect key={key} label={label} name={key} value={data[key]} onChange={handleText} options={options} />;
                    return <FInput key={key} label={label} name={key} value={data[key]} onChange={handleText} />;
                })}
            </div>

            {step === 1 && (
                <div className="mt-5 space-y-3">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Architecture Diagrams</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <FFile label="Architecture Diagram" name="architecture_diagram"
                            file={files.architecture_diagram} onChange={handleFile('architecture_diagram')} required className="md:col-span-2" />
                        {fileFields.map(([key, label]) => (
                            <FFile key={key} label={label} name={key} file={files[key]} onChange={handleFile(key)} />
                        ))}
                    </div>
                </div>
            )}

            <div className="flex justify-between mt-6 pt-4 border-t border-[#2d3748]">
                <div className="flex gap-2">
                    <Btn variant="ghost" onClick={onCancel}>Cancel</Btn>
                    {step > 0 && <Btn variant="secondary" onClick={() => setStep(s => s - 1)}>Back</Btn>}
                </div>
                {step < STEPS.length - 1
                    ? <Btn onClick={() => setStep(s => s + 1)}>Next <ChevronRight className="w-4 h-4" /></Btn>
                    : <Btn onClick={submit} loading={loading}><Save className="w-4 h-4" />{initial ? 'Update' : 'Create Assessment'}</Btn>
                }
            </div>
        </div>
    );
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
const StatCard = ({ label, value, sub, icon: Icon, color = 'blue' }) => {
    const colors = {
        blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
        red: 'text-red-400 bg-red-500/10 border-red-500/20',
        green: 'text-green-400 bg-green-500/10 border-green-500/20',
        orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    };
    return (
        <div className="bg-[#1c2230] border border-[#2d3748] rounded-xl p-4 flex items-start gap-4">
            <div className={`p-2.5 rounded-lg border flex-shrink-0 ${colors[color]}`}><Icon className="w-4 h-4" /></div>
            <div>
                <p className="text-xl font-bold text-white">{value ?? '—'}</p>
                <p className="text-xs text-slate-400 mt-0.5">{label}</p>
                {sub && <p className="text-xs text-slate-500 mt-0.5">{sub}</p>}
            </div>
        </div>
    );
};

const Dashboard = ({ stats, loading }) => {
    if (loading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>;
    if (!stats) return <EmptyState icon={BarChart3} title="No statistics yet" subtitle="Create an assessment to populate the dashboard" />;
    const { assessments: a = {}, vulnerabilities: v = {}, top_categories: cats = [] } = stats;
    return (
        <div className="space-y-5">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <StatCard icon={Shield} label="Total Assessments" value={a.total} sub={`${a.completed ?? 0} completed`} color="blue" />
                <StatCard icon={ShieldAlert} label="Vulnerabilities" value={v.total} sub={`${v.open ?? 0} open`} color="red" />
                <StatCard icon={AlertTriangle} label="Critical / High" value={(v.critical ?? 0) + (v.high ?? 0)} sub="Require attention" color="orange" />
                <StatCard icon={ShieldCheck} label="Fixed" value={v.fixed} sub="Resolved" color="green" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#1c2230] border border-[#2d3748] rounded-xl p-5">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Assessment Risk Levels</p>
                    {[
                        { label: 'High Risk', val: a.high_risk ?? 0, color: 'bg-red-500' },
                        { label: 'Medium Risk', val: a.medium_risk ?? 0, color: 'bg-yellow-500' },
                        { label: 'Low Risk', val: a.low_risk ?? 0, color: 'bg-green-500' },
                    ].map(r => (
                        <div key={r.label} className="mb-3 last:mb-0">
                            <div className="flex justify-between text-xs text-slate-400 mb-1.5"><span>{r.label}</span><span>{r.val}</span></div>
                            <div className="h-1.5 bg-slate-700/60 rounded-full overflow-hidden">
                                <div className={`h-full ${r.color} rounded-full`} style={{ width: a.total ? `${(r.val / a.total) * 100}%` : '0%' }} />
                            </div>
                        </div>
                    ))}
                </div>
                <div className="bg-[#1c2230] border border-[#2d3748] rounded-xl p-5">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Top Vulnerability Categories</p>
                    {cats.length === 0
                        ? <p className="text-xs text-slate-500">No data yet</p>
                        : cats.slice(0, 7).map((c, i) => (
                            <div key={i} className="flex items-center justify-between py-1.5 border-b border-[#2d3748] last:border-0">
                                <span className="text-xs text-slate-300 truncate">{c.category_tag}</span>
                                <span className="text-xs font-bold text-blue-400 ml-3 flex-shrink-0">{c.count}</span>
                            </div>
                        ))
                    }
                </div>
            </div>
        </div>
    );
};

// ── Activity Log ──────────────────────────────────────────────────────────────
// Assessment history shape: { id, previous_score, new_score, score_change, change_reason, changed_by, timestamp }
const ActivityLog = ({ entries, loading }) => {
    if (loading) return <div className="flex justify-center py-8"><Spinner size="lg" /></div>;
    if (!entries?.length) return <EmptyState icon={History} title="No activity yet" />;
    return (
        <div>
            {entries.map((e, i) => (
                <div key={e.id || i} className="flex gap-3">
                    <div className="flex flex-col items-center">
                        <div className="w-2 h-2 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
                        {i < entries.length - 1 && <div className="w-px flex-1 bg-[#2d3748] my-1" />}
                    </div>
                    <div className="pb-4 flex-1 min-w-0">
                        <p className="text-sm text-slate-200">
                            {e.change_reason || e.action || e.description || e.message || '—'}
                        </p>
                        <div className="flex items-center gap-3 mt-1 flex-wrap">
                            <span className="text-xs text-slate-500">{fmtDateTime(e.timestamp || e.created_at)}</span>
                            {e.changed_by && <span className="text-xs text-slate-500">by {e.changed_by}</span>}
                            {(e.previous_score != null || e.new_score != null) && (
                                <span className="text-xs text-slate-400">
                                    Score: {e.previous_score ?? '—'} → {e.new_score ?? '—'}
                                    {e.score_change != null && e.score_change !== 0 && (
                                        <span className={e.score_change > 0 ? 'text-green-400 ml-1' : 'text-red-400 ml-1'}>
                                            ({e.score_change > 0 ? '+' : ''}{e.score_change})
                                        </span>
                                    )}
                                </span>
                            )}
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

// ── Controls Panel ────────────────────────────────────────────────────────────
// Control fields: control_name, control_description, implementation_details, status,
//                 risk_reduction_percentage, verification_notes, verified_by, verified_at
// API: listControlsForVulnerability(vulnId), createControl(vulnId, data),
//      updateControl(controlId, data), deleteControl(controlId),
//      getControlUpdateHistory(controlId)
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
    const [newCtrl, setNewCtrl] = useState({
        control_name: '', control_description: '', implementation_details: '',
        status: 'pending', risk_reduction_percentage: '', verification_notes: '', verified_by: '',
    });

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const d = await listControlsForVulnerability(vulnId);
            setControls(Array.isArray(d) ? d : d?.results || []);
        } catch { setControls([]); }
        setLoading(false);
    }, [vulnId]);

    useEffect(() => { load(); }, [load]);

    const handleCreate = async () => {
        if (!newCtrl.control_name.trim()) return;
        setSaving(true);
        try {
            await createControl(vulnId, newCtrl);
            setShowAdd(false);
            setNewCtrl({ control_name: '', control_description: '', implementation_details: '', status: 'pending', risk_reduction_percentage: '', verification_notes: '', verified_by: '' });
            load();
        } catch (err) { alert(err.message); }
        setSaving(false);
    };

    const handleUpdate = async () => {
        setSaving(true);
        try { await updateControl(editId, editData); setEditId(null); load(); }
        catch (err) { alert(err.message); }
        setSaving(false);
    };

    const handleDelete = async (controlId) => {
        if (!window.confirm('Delete this control?')) return;
        try { await deleteControl(controlId); load(); }
        catch (err) { alert(err.message); }
    };

    const openHistory = async (ctrl) => {
        setHistCtrl(ctrl);
        setHistLoading(true);
        try {
            // getControlUpdateHistory returns the control object itself (same endpoint)
            // Wrap it in an array so ActivityLog can render it
            const d = await getControlUpdateHistory(ctrl.id);
            // The endpoint returns a single control object, not a list of history
            // Show the control's own fields as a single "entry"
            setHistEntries(Array.isArray(d) ? d : [d]);
        } catch { setHistEntries([]); }
        setHistLoading(false);
    };

    const CInput = ({ label, k, obj, setObj, type = 'text' }) => (
        <div>
            <label className="block text-xs text-slate-500 mb-1">{label}</label>
            {type === 'select' ? (
                <select value={obj[k] || ''} onChange={e => setObj(p => ({ ...p, [k]: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#2d3748] rounded-lg text-white text-xs focus:outline-none focus:ring-1 focus:ring-blue-500">
                    {CTRL_STATUS_OPTS.map(o => <option key={o} value={o}>{o.replace(/_/g, ' ')}</option>)}
                </select>
            ) : (
                <input type="text" value={obj[k] || ''} onChange={e => setObj(p => ({ ...p, [k]: e.target.value }))}
                    className="w-full px-3 py-1.5 bg-[#0d1117] border border-[#2d3748] rounded-lg text-white text-xs focus:outline-none focus:ring-1 focus:ring-blue-500" />
            )}
        </div>
    );

    if (loading) return <div className="flex justify-center py-4"><Spinner /></div>;

    return (
        <div className="space-y-2 mt-3">
            <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Remediation Controls ({controls.length})
                </span>
                {!showAdd && <Btn size="sm" onClick={() => setShowAdd(true)}><Plus className="w-3.5 h-3.5" />Add Control</Btn>}
            </div>

            {showAdd && (
                <div className="bg-[#0d1117] border border-blue-500/30 rounded-xl p-4 space-y-2">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <CInput label="Control Name *" k="control_name" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Status" k="status" obj={newCtrl} setObj={setNewCtrl} type="select" />
                        <CInput label="Description" k="control_description" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Implementation Details" k="implementation_details" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Risk Reduction %" k="risk_reduction_percentage" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Verified By" k="verified_by" obj={newCtrl} setObj={setNewCtrl} />
                        <CInput label="Verification Notes" k="verification_notes" obj={newCtrl} setObj={setNewCtrl} />
                    </div>
                    <div className="flex gap-2 justify-end pt-1">
                        <Btn size="sm" variant="ghost" onClick={() => setShowAdd(false)}>Cancel</Btn>
                        <Btn size="sm" onClick={handleCreate} loading={saving}><Save className="w-3.5 h-3.5" />Save</Btn>
                    </div>
                </div>
            )}

            {controls.map(c => (
                <div key={c.id} className="bg-[#0d1117] border border-[#2d3748] rounded-xl p-3">
                    {editId === c.id ? (
                        <div className="space-y-2">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                <CInput label="Control Name" k="control_name" obj={editData} setObj={setEditData} />
                                <CInput label="Status" k="status" obj={editData} setObj={setEditData} type="select" />
                                <CInput label="Description" k="control_description" obj={editData} setObj={setEditData} />
                                <CInput label="Implementation Details" k="implementation_details" obj={editData} setObj={setEditData} />
                                <CInput label="Risk Reduction %" k="risk_reduction_percentage" obj={editData} setObj={setEditData} />
                                <CInput label="Verified By" k="verified_by" obj={editData} setObj={setEditData} />
                                <CInput label="Verification Notes" k="verification_notes" obj={editData} setObj={setEditData} />
                            </div>
                            <div className="flex gap-2 justify-end">
                                <Btn size="sm" variant="ghost" onClick={() => setEditId(null)}>Cancel</Btn>
                                <Btn size="sm" onClick={handleUpdate} loading={saving}><Save className="w-3.5 h-3.5" />Save</Btn>
                            </div>
                        </div>
                    ) : (
                        <div className="flex items-start justify-between gap-2">
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <p className="text-xs font-semibold text-white">{c.control_name}</p>
                                    <StatusPill status={c.status} />
                                    {c.risk_reduction_percentage != null && (
                                        <span className="text-xs text-green-400">{c.risk_reduction_percentage}% risk reduction</span>
                                    )}
                                </div>
                                {c.control_description && <p className="text-xs text-slate-400 mt-1">{c.control_description}</p>}
                                {c.implementation_details && <p className="text-xs text-slate-500 mt-0.5 italic">{c.implementation_details}</p>}
                                {c.verified_by && <p className="text-xs text-slate-500 mt-0.5">Verified by: {c.verified_by}</p>}
                                {c.verification_notes && <p className="text-xs text-slate-500 mt-0.5">Notes: {c.verification_notes}</p>}
                            </div>
                            <div className="flex items-center gap-1 flex-shrink-0">
                                <button onClick={() => openHistory(c)} title="View" className="p-1 hover:bg-slate-700 rounded"><Eye className="w-3 h-3 text-slate-400" /></button>
                                <button onClick={() => { setEditId(c.id); setEditData({ ...c }); }} className="p-1 hover:bg-slate-700 rounded"><Edit3 className="w-3 h-3 text-slate-400" /></button>
                                <button onClick={() => handleDelete(c.id)} className="p-1 hover:bg-red-900/30 rounded"><Trash2 className="w-3 h-3 text-red-400" /></button>
                            </div>
                        </div>
                    )}
                </div>
            ))}

            {controls.length === 0 && !showAdd && <p className="text-xs text-slate-500 text-center py-3">No controls yet</p>}

            <Modal open={!!histCtrl} onClose={() => setHistCtrl(null)} title={`Control: ${histCtrl?.control_name}`}>
                {histLoading ? <div className="flex justify-center py-8"><Spinner size="lg" /></div> : (
                    <div className="space-y-3">
                        {histEntries.map((e, i) => (
                            <div key={i} className="grid grid-cols-2 gap-2">
                                {Object.entries(e).filter(([k, v]) => v && !['id'].includes(k)).map(([k, v]) => (
                                    <div key={k} className="bg-[#0d1117] rounded-lg p-2 border border-[#2d3748]">
                                        <p className="text-xs text-slate-500 capitalize">{k.replace(/_/g, ' ')}</p>
                                        <p className="text-xs text-slate-200 mt-0.5 break-words">{String(v)}</p>
                                    </div>
                                ))}
                            </div>
                        ))}
                    </div>
                )}
            </Modal>
        </div>
    );
};

// ── Vulnerabilities Panel ─────────────────────────────────────────────────────
// Vulnerability fields: id, control_title, control_description, control_impact,
//   control_recommendation, severity, status, affected_devices, category_tag,
//   framework_mapping, cvss_score, cwe_id, owasp_category, remediation_controls,
//   remediation_count, is_remediated
// update-vulnerability-status: PATCH /vulnerabilities/{vulnId}/   (flat URL)
const VULN_STATUSES = ['open', 'in_progress', 'fixed'];

const VulnerabilitiesPanel = ({ assessmentId }) => {
    const [vulns, setVulns] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState(null);
    const [updatingId, setUpdatingId] = useState(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const d = await listVulnerabilities(assessmentId);
            setVulns(Array.isArray(d) ? d : d?.results || []);
        } catch { setVulns([]); }
        setLoading(false);
    }, [assessmentId]);

    useEffect(() => { load(); }, [load]);

    const handleStatus = async (vulnId, status) => {
        setUpdatingId(vulnId);
        try {
            // API: PATCH /vulnerabilities/{vulnId}/  — only vulnId needed, no assessmentId in URL
            const updated = await updateVulnerabilityStatus(vulnId, { status });
            setVulns(prev => prev.map(v => v.id === vulnId ? { ...v, ...updated } : v));
        } catch (err) { alert(err.message); }
        setUpdatingId(null);
    };

    if (loading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>;
    if (!vulns.length) return <EmptyState icon={ShieldAlert} title="No vulnerabilities found" subtitle="Results appear after analysis completes" />;

    return (
        <div className="space-y-2">
            <p className="text-xs text-slate-500">{vulns.length} vulnerabilit{vulns.length === 1 ? 'y' : 'ies'} found</p>
            {vulns.map(v => {
                const rc = riskColor(v.severity);
                const isOpen = expanded === v.id;
                return (
                    <div key={v.id} className="bg-[#1c2230] border border-[#2d3748] rounded-xl overflow-hidden">
                        {/* Header row */}
                        <div className="p-4 flex items-start gap-3 cursor-pointer hover:bg-[#242d3d] transition-colors"
                            onClick={() => setExpanded(isOpen ? null : v.id)}>
                            <div className={`p-1.5 rounded-lg ${rc.bg} flex-shrink-0 mt-0.5`}>
                                <ShieldAlert className={`w-4 h-4 ${rc.text}`} />
                            </div>
                            <div className="flex-1 min-w-0">
                                {/* Title is control_title in API response */}
                                <div className="flex items-start justify-between gap-2 flex-wrap">
                                    <p className="text-sm font-semibold text-white">{v.control_title}</p>
                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <Badge label={v.severity} />
                                        <StatusPill status={v.status} />
                                    </div>
                                </div>
                                <div className="flex items-center gap-3 mt-1 flex-wrap">
                                    {v.category_tag && <span className="text-xs text-blue-400/80">{v.category_tag}</span>}
                                    {v.affected_devices && <span className="text-xs text-slate-500">Device: {v.affected_devices}</span>}
                                    {v.cvss_score && <span className="text-xs text-slate-500">CVSS: {v.cvss_score}</span>}
                                    {v.cwe_id && <span className="text-xs text-slate-500">{v.cwe_id}</span>}
                                </div>
                                {v.control_description && (
                                    <p className="text-xs text-slate-400 mt-1 line-clamp-1">{v.control_description}</p>
                                )}
                            </div>
                            {isOpen ? <ChevronUp className="w-4 h-4 text-slate-400 flex-shrink-0 mt-1" /> : <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0 mt-1" />}
                        </div>

                        {/* Expanded detail */}
                        {isOpen && (
                            <div className="border-t border-[#2d3748] p-4 bg-[#161b22] space-y-4">
                                {/* Details grid */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {v.control_description && (
                                        <div className="md:col-span-2">
                                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Description</p>
                                            <p className="text-sm text-slate-300">{v.control_description}</p>
                                        </div>
                                    )}
                                    {v.control_impact && (
                                        <div>
                                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Impact</p>
                                            <p className="text-sm text-slate-300">{v.control_impact}</p>
                                        </div>
                                    )}
                                    {v.control_recommendation && (
                                        <div>
                                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Recommendation</p>
                                            <p className="text-sm text-slate-300">{v.control_recommendation}</p>
                                        </div>
                                    )}
                                    {v.owasp_category && (
                                        <div>
                                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">OWASP Category</p>
                                            <p className="text-sm text-slate-300">{v.owasp_category}</p>
                                        </div>
                                    )}
                                    {v.framework_mapping && (
                                        <div>
                                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Framework Mapping</p>
                                            <p className="text-sm text-slate-300">{v.framework_mapping}</p>
                                        </div>
                                    )}
                                </div>

                                {/* Remediation info */}
                                <div className="flex items-center gap-4 text-xs text-slate-400">
                                    <span>Remediation controls: <span className="text-white font-medium">{v.remediation_count ?? 0}</span></span>
                                    <span>Remediated: <span className={v.is_remediated ? 'text-green-400 font-medium' : 'text-red-400 font-medium'}>{v.is_remediated ? 'Yes' : 'No'}</span></span>
                                </div>

                                {/* Status update */}
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Update Status</p>
                                    <div className="flex gap-2 flex-wrap">
                                        {VULN_STATUSES.map(s => (
                                            <button key={s} onClick={() => handleStatus(v.id, s)}
                                                disabled={updatingId === v.id}
                                                className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all
                          ${v.status === s ? 'border-blue-500 bg-blue-500/20 text-blue-300' : 'border-[#2d3748] text-slate-400 hover:border-slate-500 hover:text-white'}`}>
                                                {updatingId === v.id && v.status !== s ? <Spinner /> : null}
                                                {s.replace('_', ' ')}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                {/* Controls panel — only needs vulnId */}
                                <ControlsPanel vulnId={v.id} />
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

// ── Assessment Detail ─────────────────────────────────────────────────────────
// assessment-details response includes: id, vulnerable_components (array), overall_risk_score,
// status, vulnerability_count, critical_count, high_count, application_purpose, + all form fields
const AssessmentDetail = ({ assessment, onBack, onDeleted, onUpdated }) => {
    const [details, setDetails] = useState(assessment);
    const [detailsLoading, setDL] = useState(true);
    const [tab, setTab] = useState('vulnerabilities');
    const [history, setHistory] = useState([]);
    const [histLoading, setHistLoading] = useState(false);
    const [showEdit, setShowEdit] = useState(false);
    const [saving, setSaving] = useState(false);
    const [downloading, setDL2] = useState(false);
    const [deleting, setDeleting] = useState(false);

    useEffect(() => {
        (async () => {
            setDL(true);
            try { setDetails(await getAssessmentDetails(assessment.id)); } catch { }
            setDL(false);
        })();
    }, [assessment.id]);

    const loadHistory = useCallback(async () => {
        setHistLoading(true);
        try {
            const h = await getAssessmentHistory(assessment.id);
            setHistory(Array.isArray(h) ? h : h?.results || []);
        } catch { setHistory([]); }
        setHistLoading(false);
    }, [assessment.id]);

    useEffect(() => { if (tab === 'history') loadHistory(); }, [tab, loadHistory]);

    const handleDownload = async () => {
        setDL2(true);
        try { await downloadExcelReport(assessment.id); }
        catch (err) { alert(err.message); }
        setDL2(false);
    };

    const handleDelete = async () => {
        if (!window.confirm('Permanently delete this assessment? This cannot be undone.')) return;
        setDeleting(true);
        try { await deleteAssessment(assessment.id); onDeleted(assessment.id); }
        catch (err) { alert(err.message); setDeleting(false); }
    };

    const handleUpdate = async (fd) => {
        setSaving(true);
        try {
            const updated = await updateAssessment(assessment.id, fd);
            setDetails(updated);
            setShowEdit(false);
            onUpdated(updated);
        } catch (err) { alert(err.message); }
        setSaving(false);
    };

    const TABS = [
        { key: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
        { key: 'history', label: 'Activity Log', icon: History },
        { key: 'details', label: 'All Details', icon: Info },
    ];

    const rc = details?.overall_risk_score != null
        ? (details.overall_risk_score >= 70 ? riskColor('high') : details.overall_risk_score >= 40 ? riskColor('medium') : riskColor('low'))
        : riskColor('');

    return (
        <div className="space-y-5">
            {/* Header */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                    <button onClick={onBack} className="p-2 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-4 h-4" />
                    </button>
                    <div>
                        <h2 className="text-lg font-bold text-white line-clamp-2">
                            {details?.application_purpose || details?.application_type || 'Assessment'}
                        </h2>
                        <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                            <StatusPill status={details?.status} />
                            {details?.overall_risk_score != null && (
                                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${rc.bg} ${rc.text} ${rc.border}`}>
                                    Risk Score: {details.overall_risk_score}
                                </span>
                            )}
                            <span className="text-xs text-slate-500">{fmtDate(details?.created_at)}</span>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                    <Btn size="sm" variant="success" onClick={handleDownload} loading={downloading}><Download className="w-4 h-4" />Excel Report</Btn>
                    <Btn size="sm" variant="secondary" onClick={() => setShowEdit(true)}><Edit3 className="w-4 h-4" />Edit</Btn>
                    <Btn size="sm" variant="danger" onClick={handleDelete} loading={deleting}><Trash2 className="w-4 h-4" />Delete</Btn>
                </div>
            </div>

            {/* Quick-info chips */}
            {detailsLoading
                ? <div className="flex justify-center py-4"><Spinner size="lg" /></div>
                : (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {[
                            { label: 'Vulnerabilities', value: details?.vulnerability_count ?? '—' },
                            { label: 'Critical', value: details?.critical_count ?? '—' },
                            { label: 'High', value: details?.high_count ?? '—' },
                            { label: 'Application Type', value: details?.application_type || '—' },
                        ].map(item => (
                            <div key={item.label} className="bg-[#1c2230] border border-[#2d3748] rounded-lg p-3">
                                <p className="text-xs text-slate-500">{item.label}</p>
                                <p className="text-sm font-medium text-white mt-0.5">{item.value}</p>
                            </div>
                        ))}
                    </div>
                )
            }

            {/* Tabs */}
            <div className="flex border-b border-[#2d3748]">
                {TABS.map(t => {
                    const Icon = t.icon;
                    return (
                        <button key={t.key} onClick={() => setTab(t.key)}
                            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all border-b-2 -mb-px
                ${tab === t.key ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-white'}`}>
                            <Icon className="w-4 h-4" />{t.label}
                        </button>
                    );
                })}
            </div>

            {tab === 'vulnerabilities' && <VulnerabilitiesPanel assessmentId={assessment.id} />}
            {tab === 'history' && <ActivityLog entries={history} loading={histLoading} />}
            {tab === 'details' && details && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                    {Object.entries(details)
                        .filter(([k, v]) => !['id', 'vulnerable_components'].includes(k) && v != null && v !== '')
                        .map(([k, v]) => (
                            <div key={k} className="bg-[#1c2230] border border-[#2d3748] rounded-lg p-3">
                                <p className="text-xs text-slate-500 capitalize">{k.replace(/_/g, ' ')}</p>
                                <p className="text-sm text-slate-200 mt-0.5 break-words">{typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v)}</p>
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

// ── Assessment List Panel ─────────────────────────────────────────────────────
// list-assessments shape: { id, created_at, updated_at, status, overall_risk_score,
//   vulnerability_count, critical_count, high_count, application_purpose }
const AssessmentListPanel = ({ assessments, selected, onSelect, onDeleted }) => {
    const [deleting, setDeleting] = useState(null);

    const handleDelete = async (e, id) => {
        e.stopPropagation();
        if (!window.confirm('Delete this assessment?')) return;
        setDeleting(id);
        try { await deleteAssessment(id); onDeleted(id); }
        catch (err) { alert(err.message); }
        setDeleting(null);
    };

    if (!assessments.length) return <EmptyState icon={ClipboardList} title="No assessments yet" subtitle="Create one to get started" />;

    return (
        <div className="space-y-2">
            {assessments.map(a => (
                <div key={a.id} onClick={() => onSelect(a)}
                    className={`relative p-3.5 rounded-xl border cursor-pointer transition-all hover:border-blue-500/50 group
            ${selected?.id === a.id ? 'border-blue-500/60 bg-[#1c2230]' : 'border-[#2d3748] bg-[#161b22] hover:bg-[#1c2230]'}`}>
                    <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                                <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${a.status === 'completed' ? 'bg-green-400' : a.status === 'failed' ? 'bg-red-400' : 'bg-blue-400'}`} />
                                <p className="text-xs font-semibold text-white truncate">
                                    {a.application_purpose?.slice(0, 40) || 'Assessment'}
                                </p>
                            </div>
                            <div className="flex items-center gap-2 pl-3.5 flex-wrap">
                                <StatusPill status={a.status} />
                                {a.overall_risk_score != null && (
                                    <span className="text-xs text-slate-400">Score: {a.overall_risk_score}</span>
                                )}
                            </div>
                            <div className="flex items-center gap-3 mt-1 pl-3.5 text-xs text-slate-500 flex-wrap">
                                {a.vulnerability_count > 0 && <span>{a.vulnerability_count} vulns</span>}
                                {a.critical_count > 0 && <span className="text-red-400">{a.critical_count} critical</span>}
                                <span>{fmtDate(a.created_at)}</span>
                            </div>
                        </div>
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                            <button onClick={e => handleDelete(e, a.id)} disabled={deleting === a.id}
                                className="p-1 hover:bg-red-900/30 rounded transition-colors">
                                {deleting === a.id ? <Spinner /> : <Trash2 className="w-3 h-3 text-red-400" />}
                            </button>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

// ── Main Page ─────────────────────────────────────────────────────────────────
const ArchitectureAssessmentPage = () => {
    const [view, setView] = useState('dashboard');
    const [assessments, setAssessments] = useState([]);
    const [aLoading, setALoading] = useState(true);
    const [stats, setStats] = useState(null);
    const [sLoading, setSLoading] = useState(true);
    const [selected, setSelected] = useState(null);
    const [creating, setCreating] = useState(false);

    const load = useCallback(async () => {
        setALoading(true); setSLoading(true);
        const [a, s] = await Promise.allSettled([listAssessments(), getStatistics()]);
        if (a.status === 'fulfilled') setAssessments(Array.isArray(a.value) ? a.value : a.value?.results || []);
        if (s.status === 'fulfilled') setStats(s.value);
        setALoading(false); setSLoading(false);
    }, []);

    useEffect(() => { load(); }, [load]);

    const handleCreate = async (fd) => {
        setCreating(true);
        try { const n = await createAssessment(fd); setAssessments(p => [n, ...p]); setView('dashboard'); load(); }
        catch (err) { alert(err.message); }
        setCreating(false);
    };

    const handleDeleted = (id) => {
        setAssessments(p => p.filter(a => a.id !== id));
        if (selected?.id === id) { setSelected(null); setView('dashboard'); }
        load();
    };

    const handleUpdated = (u) => setAssessments(p => p.map(a => a.id === u.id ? u : a));
    const selectAssessment = (a) => { setSelected(a); setView('detail'); };

    return (
        <div className="min-h-screen bg-[#0d1117] font-sans text-white">
            {/* Nav */}
            <header className="border-b border-[#2d3748] bg-[#0d1117]/95 sticky top-0 z-40 backdrop-blur">
                <div className="max-w-screen-2xl mx-auto px-6 h-14 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        {view !== 'dashboard' && (
                            <button onClick={() => setView('dashboard')}
                                className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors">
                                <ArrowLeft className="w-4 h-4" />
                            </button>
                        )}
                        <Shield className="w-5 h-5 text-blue-400" />
                        <span className="text-sm font-bold">AI Architecture Risk Assessment</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <button onClick={load} className="p-2 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors" title="Refresh">
                            <RefreshCw className="w-4 h-4" />
                        </button>
                        {view !== 'create' && (
                            <Btn size="sm" onClick={() => setView('create')}><Plus className="w-4 h-4" />New Assessment</Btn>
                        )}
                    </div>
                </div>
            </header>

            {/* Heading */}
            <div className="max-w-screen-2xl mx-auto px-6 pt-8 pb-5">
                {view === 'dashboard' && <>
                    <h1 className="text-3xl md:text-4xl font-bold">AI Architecture Risk Assessment</h1>
                    <p className="text-slate-400 text-sm mt-1.5">Comprehensive AI-powered Architecture Risking and security assessment tools</p>
                </>}
                {view === 'create' && <>
                    <h1 className="text-3xl font-bold">Create New Assessment</h1>
                    <p className="text-slate-400 text-sm mt-1.5">Architecture Diagram upload is required. All other fields are optional.</p>
                </>}
                {view === 'detail' && <>
                    <h1 className="text-3xl font-bold">Assessment Details</h1>
                    <p className="text-slate-400 text-sm mt-1.5">Vulnerabilities, controls, and activity history</p>
                </>}
            </div>

            <main className="max-w-screen-2xl mx-auto px-6 pb-12">
                {view === 'create' && (
                    <div className="bg-[#161b22] border border-[#2d3748] rounded-2xl p-6">
                        <AssessmentForm onSubmit={handleCreate} onCancel={() => setView('dashboard')} loading={creating} />
                    </div>
                )}

                {view === 'detail' && selected && (
                    <div className="bg-[#161b22] border border-[#2d3748] rounded-2xl p-6">
                        <AssessmentDetail assessment={selected} onBack={() => setView('dashboard')} onDeleted={handleDeleted} onUpdated={handleUpdated} />
                    </div>
                )}

                {view === 'dashboard' && (
                    <div className="flex gap-5">
                        {/* Left — history list */}
                        <div className="w-72 flex-shrink-0">
                            <div className="bg-[#161b22] border border-[#2d3748] rounded-2xl overflow-hidden">
                                <div className="px-4 py-3.5 border-b border-[#2d3748] flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <Clock className="w-4 h-4 text-blue-400" />
                                        <span className="text-sm font-semibold">Recent Assessments</span>
                                    </div>
                                    {aLoading && <Spinner />}
                                </div>
                                <div className="p-3 max-h-[calc(100vh-300px)] overflow-y-auto">
                                    <AssessmentListPanel assessments={assessments} selected={selected} onSelect={selectAssessment} onDeleted={handleDeleted} />
                                </div>
                                {/* <div className="px-3 pb-3 pt-3 border-t border-[#2d3748]">
                                    <button onClick={() => setView('create')}
                                        className="w-full flex items-center justify-center gap-2 py-2.5 border border-[#2d3748] hover:border-blue-500/50 hover:bg-[#1c2230] rounded-xl text-slate-400 hover:text-white text-sm transition-all">
                                        <Plus className="w-4 h-4" />New Assessment
                                    </button>
                                </div> */}
                            </div>
                        </div>

                        {/* Right — dashboard */}
                        <div className="flex-1 min-w-0 space-y-4">
                            <div className="bg-[#161b22] border border-[#2d3748] rounded-2xl p-6">
                                <div className="flex items-center gap-2 mb-5">
                                    <BarChart3 className="w-4 h-4 text-blue-400" />
                                    <h2 className="text-sm font-bold">Security Overview</h2>
                                </div>
                                <Dashboard stats={stats} loading={sLoading} />
                            </div>

                            {assessments.length > 0 && (
                                <div className="bg-[#161b22] border border-[#2d3748] rounded-2xl p-6">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center gap-2">
                                            <Eye className="w-4 h-4 text-blue-400" />
                                            <h2 className="text-sm font-bold">Latest Assessment</h2>
                                        </div>
                                        <Btn size="sm" variant="ghost" onClick={() => selectAssessment(assessments[0])}>
                                            View Details <ChevronRight className="w-4 h-4" />
                                        </Btn>
                                    </div>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                        {[
                                            { label: 'Purpose', value: assessments[0].application_purpose?.slice(0, 50) },
                                            { label: 'Status', value: <StatusPill status={assessments[0].status} /> },
                                            { label: 'Risk Score', value: assessments[0].overall_risk_score ?? '—' },
                                            { label: 'Findings', value: assessments[0].vulnerability_count ?? '—' },
                                        ].map(item => (
                                            <div key={item.label} className="bg-[#0d1117] border border-[#2d3748] rounded-lg p-3">
                                                <p className="text-xs text-slate-500">{item.label}</p>
                                                <div className="text-sm text-slate-200 mt-0.5 truncate font-medium">{item.value}</div>
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
    );
};

export default ArchitectureAssessmentPage;