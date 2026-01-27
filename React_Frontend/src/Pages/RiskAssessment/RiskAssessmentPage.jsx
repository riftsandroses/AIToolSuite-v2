import React, { useState } from 'react';
import {
  ArrowLeft,
  FileText,
  Database,
  Activity,
  Shield,
  BarChart3,
  Cloud,
  Upload,
  X,
  Code,
  Smartphone,
  Briefcase,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Plus,
  Edit,
  Trash2,
  Brain,
  ChevronDown
} from 'lucide-react';

// --- UI Components ---

// Risk Chip
const RiskChip = ({ label, size = "medium" }) => {
  const getColorClasses = () => {
    const labelLower = label.toLowerCase();
    if (['high', 'error', 'critical'].includes(labelLower)) {
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    }
    if (['medium', 'warning', 'moderate'].includes(labelLower)) {
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    }
    return 'bg-green-500/20 text-green-400 border-green-500/30';
  };

  const sizeClasses = size === 'small' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span className={`inline-flex items-center rounded-full border ${getColorClasses()} ${sizeClasses} font-medium`}>
      {label}
    </span>
  );
};

// Custom Styled Dropdown
const CustomSelect = ({ label, name, value, onChange, options, placeholder = "Select an option" }) => (
  <div className="w-full">
    <label className="block text-sm font-medium text-blue-400 mb-2">
      {label}
    </label>
    <div className="relative">
      <select
        name={name}
        value={value || ''}
        onChange={onChange}
        className="w-full appearance-none px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all cursor-pointer"
      >
        <option value="" disabled>{placeholder}</option>
        {options.map(opt => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
      <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
    </div>
  </div>
);

// --- Form Steps Components ---

const AppInformation = ({ formData, handleInputChange, handleTechStackChange, handleFileChange, handleRemoveFile }) => {
  const appTypeOptions = [
    { value: 'web', label: 'Web Application' },
    { value: 'mobile', label: 'Mobile Application' },
    { value: 'desktop', label: 'Desktop Application' },
    { value: 'api', label: 'API/Backend Service' }
  ];

  const platformOptions = [
    { value: 'web', label: 'Web' },
    { value: 'ios', label: 'iOS' },
    { value: 'android', label: 'Android' },
    { value: 'windows', label: 'Windows' },
    { value: 'macos', label: 'macOS' },
    { value: 'linux', label: 'Linux' }
  ];

  const techStackOptions = {
    frontend: [
      { value: 'react', label: 'React' },
      { value: 'vue', label: 'Vue.js' },
      { value: 'angular', label: 'Angular' },
      { value: 'svelte', label: 'Svelte' }
    ],
    backend: [
      { value: 'nodejs', label: 'Node.js' },
      { value: 'python', label: 'Python' },
      { value: 'java', label: 'Java' },
      { value: 'dotnet', label: '.NET' }
    ],
    database: [
      { value: 'postgresql', label: 'PostgreSQL' },
      { value: 'mysql', label: 'MySQL' },
      { value: 'mongodb', label: 'MongoDB' },
      { value: 'redis', label: 'Redis' }
    ]
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <FileText className="w-6 h-6 text-blue-400" />
        <h3 className="text-xl font-semibold text-white">Application Information</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-blue-400 mb-2">Application Name</label>
          <input
            type="text"
            name="application_name"
            value={formData.application_name || ''}
            onChange={handleInputChange}
            placeholder="Enter application name"
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <CustomSelect
          label="Application Type"
          name="application_type"
          value={formData.application_type}
          onChange={handleInputChange}
          options={appTypeOptions}
        />

        <CustomSelect
          label="Platforms"
          name="platforms"
          value={formData.platforms}
          onChange={handleInputChange}
          options={platformOptions}
        />

        <div>
          <label className="text-sm font-medium text-blue-400 mb-2 flex items-center gap-2">
            <Briefcase className="w-4 h-4" />
            Business Logic
          </label>
          <textarea
            name="business_logic"
            value={formData.business_logic || ''}
            onChange={handleInputChange}
            placeholder="Describe the business logic and purpose of the application"
            rows={3}
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
          />
        </div>
      </div>

      {/* Tech Stack Section */}
      <div className="mt-8">
        <label className="text-sm font-medium text-blue-400 mb-4 flex items-center gap-2">
          <Code className="w-4 h-4" />
          Tech Stack
        </label>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <CustomSelect
            label="Frontend"
            name="frontend"
            value={formData.frontend}
            onChange={(e) => handleTechStackChange('frontend', e.target.value)}
            options={techStackOptions.frontend}
            placeholder="Select Frontend Tech"
          />
          <CustomSelect
            label="Backend"
            name="backend"
            value={formData.backend}
            onChange={(e) => handleTechStackChange('backend', e.target.value)}
            options={techStackOptions.backend}
            placeholder="Select Backend Tech"
          />
          <CustomSelect
            label="Database"
            name="database"
            value={formData.database}
            onChange={(e) => handleTechStackChange('database', e.target.value)}
            options={techStackOptions.database}
            placeholder="Select Database"
          />
        </div>

        {/* Architecture Diagram Upload */}
        <div className="mt-6">
          <label className="block text-xs font-medium text-slate-400 mb-2">
            Upload Architecture Diagram
          </label>
          {formData.tech_stack_file ? (
            <div className="flex items-center justify-between px-4 py-2.5 bg-slate-800/50 border border-slate-700 rounded-lg">
              <span className="text-white text-sm truncate">{formData.tech_stack_file.name}</span>
              <button onClick={() => handleRemoveFile('tech_stack_file')} className="text-slate-400 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <label className="flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-800/50 border border-slate-700 rounded-lg cursor-pointer hover:bg-slate-800 transition-colors">
              <Upload className="w-4 h-4 text-slate-400" />
              <span className="text-slate-400 text-sm">Select File...</span>
              <input type="file" name="tech_stack_file" onChange={handleFileChange} className="hidden" />
            </label>
          )}
        </div>
      </div>

      {/* SOW/Proposal Upload */}
      <div>
        <label className="text-sm font-medium text-blue-400 mb-2 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          SOW/Proposal
        </label>
        {formData.sow_proposal_file ? (
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-800/50 border border-slate-700 rounded-lg">
            <span className="text-white text-sm truncate">{formData.sow_proposal_file.name}</span>
            <button
              onClick={() => handleRemoveFile('sow_proposal_file')}
              className="text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <label className="flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-800/50 border border-slate-700 rounded-lg cursor-pointer hover:bg-slate-800 transition-colors">
            <Upload className="w-4 h-4 text-slate-400" />
            <span className="text-slate-400 text-sm">Select File...</span>
            <input
              type="file"
              name="sow_proposal_file"
              onChange={handleFileChange}
              className="hidden"
            />
          </label>
        )}
      </div>
    </div>
  );
};

const ArchitectureHosting = ({ formData, handleInputChange }) => {
  const architectureOptions = [
    { value: 'monolithic', label: 'Monolithic' },
    { value: 'microservices', label: 'Microservices' },
    { value: 'serverless', label: 'Serverless' },
    { value: 'hybrid', label: 'Hybrid' }
  ];

  const hostingOptions = [
    { value: 'aws', label: 'AWS' },
    { value: 'azure', label: 'Azure' },
    { value: 'gcp', label: 'Google Cloud' },
    { value: 'on-premise', label: 'On-Premise' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <Cloud className="w-6 h-6 text-blue-400" />
        <h3 className="text-xl font-semibold text-white">Architecture and Hosting</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <CustomSelect
          label="Architecture"
          name="architecture"
          value={formData.architecture}
          onChange={handleInputChange}
          options={architectureOptions}
        />
        <CustomSelect
          label="Hosting"
          name="hosting"
          value={formData.hosting}
          onChange={handleInputChange}
          options={hostingOptions}
        />
      </div>
    </div>
  );
};

const RiskSecurity = ({ formData, handleInputChange }) => {
  const options = {
    data_security: ['none', 'basic', 'advanced', 'enterprise'],
    sensitive_data: ['none', 'pii', 'financial', 'health', 'combined'],
    third_party_integrations: ['none', 'minimal', 'moderate', 'extensive'],
    error_handling: ['none', 'basic', 'comprehensive', 'advanced'],
    user_input_handling: ['text_only', 'file_upload', 'mixed', 'complex'],
    monitoring: ['none', 'basic', 'comprehensive', 'advanced'],
    legacy_dependencies: ['none', 'minimal', 'moderate', 'extensive']
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <Shield className="w-6 h-6 text-blue-400" />
        <h3 className="text-xl font-semibold text-white">Risk and Security</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(options).map(([key, values]) => (
          <CustomSelect
            key={key}
            label={key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
            name={key}
            value={formData[key]}
            onChange={handleInputChange}
            options={values.map(v => ({
              value: v,
              label: v.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
            }))}
          />
        ))}
      </div>
    </div>
  );
};

// --- AI Risk Assessment Component ---
const AIRiskAssessment = ({ formData, handleInputChange }) => {
  const dataTypeOptions = [
    { value: 'public_data', label: 'Public Data' },
    { value: 'internal_business_data', label: 'Internal Business Data' },
    { value: 'pii', label: 'PII' },
    { value: 'financial_data', label: 'Financial Data' },
    { value: 'health_data', label: 'Health Data' },
    { value: 'behavioral_data', label: 'Behavioral Data' },
    { value: 'transactional_data', label: 'Transactional Data' },
    { value: 'market_data', label: 'Market Data' },
    { value: 'cybersecurity_data', label: 'Cybersecurity Data' },
    { value: 'geographical_data', label: 'Geographical Data' },
    { value: 'environmental_data', label: 'Environmental Data' },
    { value: 'regulatory_data', label: 'Regulatory Data' },
    { value: 'biometrics', label: 'Biometrics' },
    { value: 'other', label: 'Other (PHI, PCI, Background Checks)' }
  ];

  const dataStructureOptions = [
    { value: 'text_documents', label: 'Text Documents' },
    { value: 'image_documents', label: 'Image Documents' },
    { value: 'graph_documents', label: 'Graph Documents' },
    { value: 'videos', label: 'Videos' },
    { value: 'code', label: 'Code' }
  ];

  const sensitivityOptions = [
    { value: 'low', label: 'Low Sensitivity' },
    { value: 'moderate', label: 'Moderate Sensitivity' },
    { value: 'high', label: 'High Sensitivity' },
    { value: 'critical', label: 'Critical Sensitivity' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <Brain className="w-6 h-6 text-blue-400" />
        <h3 className="text-xl font-semibold text-white">AI Risk Assessment</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <CustomSelect
          label="What kind of data does your application process?"
          name="ai_data_types"
          value={formData.ai_data_types}
          onChange={handleInputChange}
          options={dataTypeOptions}
        />

        <CustomSelect
          label="What is the structure of data that the application processes?"
          name="ai_data_structure"
          value={formData.ai_data_structure}
          onChange={handleInputChange}
          options={dataStructureOptions}
        />

        <CustomSelect
          label="How sensitive is the processed data?"
          name="ai_data_sensitivity"
          value={formData.ai_data_sensitivity}
          onChange={handleInputChange}
          options={sensitivityOptions}
        />

        <CustomSelect
          label="Is any sensitive data shared with third-party services?"
          name="ai_third_party_sharing"
          value={formData.ai_third_party_sharing}
          onChange={handleInputChange}
          options={[
            { value: 'yes', label: 'Yes' },
            { value: 'no', label: 'No' },
            { value: 'unsure', label: 'Unsure' }
          ]}
        />
      </div>

      {formData.ai_third_party_sharing === 'yes' && (
        <div className="mt-4 animate-in fade-in slide-in-from-top-2">
          <label className="block text-sm font-medium text-blue-400 mb-2">
            If Yes, specify the type of data being shared
          </label>
          <textarea
            name="ai_shared_data_details"
            value={formData.ai_shared_data_details || ''}
            onChange={handleInputChange}
            placeholder="Describe what type of data is shared with third parties..."
            rows={3}
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
          />
        </div>
      )}
    </div>
  );
};

// --- Static Risk Analysis with ALL Tables ---
const StaticRiskAnalysis = ({ formData }) => {

  const getAIScenario = () => {
    const type = formData.ai_data_types;
    const structure = formData.ai_data_structure;
    const sensitivity = formData.ai_data_sensitivity;
    const sharing = formData.ai_third_party_sharing;

    // Scenario 1: Health Data (High Risk)
    if (
      type === 'health_data' &&
      structure === 'text_documents' &&
      sensitivity === 'high' &&
      sharing === 'yes'
    ) {
      return {
        score: 78,
        riskDescription: "Insufficient Data Retention & High Sensitivity Exposure",
        observation: "The application processes highly sensitive health data in text-document form—including patient medical history and blood type—and this sensitive information is also shared with third-party services.",
        impact: "Handling and externally sharing such high-sensitivity medical data significantly increases the risk of privacy breaches, regulatory non-compliance (HIPAA/GDPR), unauthorized disclosure through third-party vulnerabilities, reputational damage, and legal or financial penalties.",
        category: "Data Sensitivity & Privacy",
        recommendation: "Implement strict end-to-end data protection measures such as encryption in transit and at rest, strong role-based access controls, data minimization, and pseudonymization before sharing; perform thorough third-party security and compliance assessments; establish Data Processing Agreements (DPAs); enforce continuous monitoring and audit logging; and ensure all data handling aligns with healthcare security and privacy regulations.",
        rating: "High"
      };
    }

    // Scenario 2: Public Data (Low Risk)
    if (
      type === 'public_data' &&
      structure === 'text_documents' &&
      sensitivity === 'low' &&
      sharing === 'yes'
    ) {
      return {
        score: 25,
        riskDescription: "Public Data Integrity Risk",
        observation: "The application processes public, low-sensitivity data in text-document form, extracted from government hospital records that do not contain any PII, and shares this non-sensitive data with third-party services.",
        impact: "Because the data is publicly available and contains no personal or identifiable information, the overall confidentiality risk is low; however, third-party integrations still introduce minimal operational and integrity risks if the data is altered, misused, or improperly handled.",
        category: "Integrity & Availability",
        recommendation: "Maintain standard security practices such as API access controls, data validation, and vendor reliability checks to ensure the accuracy and integrity of the public data being shared. Although risk is low, periodically review third-party agreements and ensure proper logging and monitoring to prevent unauthorized modifications or misuse of the sourced public information.",
        rating: "Low"
      };
    }

    return null;
  };

  const aiScenario = getAIScenario();
  const baseRiskScore = aiScenario ? aiScenario.score : 82;
  const appName = formData.application_name || "SuperFast Bank: Data Miner";
  const appDesc = formData.business_logic || "SuperFast Bank: Data Miner is a Python-based data processing and insights-generation tool designed for structured and semi-structured data. The tool will be integrated into SuperFast Bank’s data analytics ecosystem and aligned with the bank’s security, governance, and compliance standards....";

  const sharedDataSummary = formData.ai_third_party_sharing === 'yes'
    ? `${formData.ai_data_types?.replace(/_/g, ' ').toUpperCase()}: ${formData.ai_shared_data_details || 'User data processed by third party LLM providers.'}`
    : "Internal Processing: No sensitive data shared externally.";

  // Static vulnerabilities data
  const staticVulnerabilities = [
    {
      id: 1,
      component: "pandas",
      version: "1.5.3",
      cve: "CVE-2024-34341",
      severity: "High",
      summary: "Arbitrary file read vulnerability via crafted Excel files."
    },
    {
      id: 2,
      component: "psycopg2-binary",
      version: "2.9.1",
      cve: "CVE-2022-31101",
      severity: "Medium",
      summary: "SQL injection vulnerability in 'format_binary' function."
    },
    {
      id: 3,
      component: "Django",
      version: "4.1.7",
      cve: "CVE-2023-46695",
      severity: "Low",
      summary: "Potential Denial-of-Service (DoS) in 'intcomma' template filter."
    }
  ];

  const staticMitreSoTRisks = [
    {
      id: "SoT-1",
      risk: "Using Vulnerable Components",
      example: "The tool's core dependency, `pandas` v1.5.3, has a known 'High' severity vulnerability (CVE-2024-34341).",
      mitigation: "Implement a Software Bill of Materials (SBOM) and integrate continuous vulnerability scanning (e.g., Snyk, Dependabot) into the CI/CD pipeline."
    },
    {
      id: "SoT-3",
      risk: "Compromised Build Process",
      example: "The build pipeline pulls dependencies directly from the public PyPI repository without verifying package signatures or hashes.",
      mitigation: "Use a private artifact repository (e.g., Artifactory, Nexus) as a proxy. Enforce dependency hash-checking in `requirements.txt`."
    },
    {
      id: "SoT-5",
      risk: "Insufficient Dependency Management",
      example: "The `requirements.txt` file contains several unpinned dependencies (e.g., `numpy>=1.20`), leading to non-deterministic builds.",
      mitigation: "Pin all dependencies to specific, vetted versions (e.g., `pandas==2.2.2`). Use tools like `pip-compile` or `Poetry` to manage lock files."
    }
  ];

  const staticMitigations = [
    {
      id: 1,
      recommendation: "Upgrade 'pandas' library",
      details: "Upgrade pandas from v1.5.3 to v2.2.2 or later to patch the arbitrary file read vulnerability (CVE-2024-34341)."
    },
    {
      id: 2,
      recommendation: "Upgrade PostgreSQL Driver",
      details: "Upgrade 'psycopg2-binary' from v2.9.1 to v2.9.4 or later to mitigate the SQL injection risk (CVE-2022-31101)."
    },
    {
      id: 3,
      recommendation: "Implement Strict Query Parameterization",
      details: "Rely on Django's ORM and avoid raw SQL queries where possible. All user-controlled inputs must be parameterized."
    }
  ];

  // Two static rows for detailed observations
  const staticObservations = [
    {
      id: 1,
      riskDescription: "Insufficient Data Retention Controls",
      observation: "It was observed that customer conversation data is retained indefinitely without clear retention policies or automated deletion mechanisms aligned with regulatory requirements.",
      impact: "Excessive data retention increases privacy risks, potential regulatory non-compliance (GDPR, CCPA), and exposure to data breaches affecting customer trust and legal liability.",
      category: "Data Sensitivity",
      rating: "High",
      recommendation: "It is recommended to implement automated data retention policies with configurable retention periods, establish data minimization practices, and provide users with data deletion requests capabilities."
    },
    {
      id: 2,
      riskDescription: "Limited Model Explainability",
      observation: "It was observed that the AI system provides responses without explanation of reasoning, confidence levels, or source attribution, making it difficult for users to understand decision-making processes.",
      impact: "Lack of explainability reduces user trust, makes debugging difficult, and may lead to acceptance of incorrect or biased outputs without critical evaluation.",
      category: "Explainability & Safety",
      rating: "High",
      recommendation: "It is recommended to implement explanation interfaces showing reasoning steps, confidence scores, and source citations. Deploy interpretability tools and maintain audit trails for critical decisions."
    }
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3">
        <BarChart3 className="w-6 h-6 text-blue-400" />
        <h3 className="text-xl font-semibold text-white">
          Risk Analysis for: {appName}
        </h3>
      </div>

      {/* Overall Risk Score - MOVED TO TOP */}
      <div>
        <h4 className="text-lg font-medium text-white mb-4">Overall Risk Score</h4>
        <div className="flex items-center gap-4 mb-3">
          <span className={`text-5xl font-bold ${baseRiskScore > 70 ? 'text-red-400' : baseRiskScore > 40 ? 'text-yellow-400' : 'text-green-400'}`}>
            {baseRiskScore}
          </span>
          <RiskChip label={baseRiskScore > 70 ? 'High Risk' : baseRiskScore > 40 ? 'Medium Risk' : 'Low Risk'} />
        </div>
        <div className="w-full bg-slate-700 rounded-full h-4">
          <div
            className={`h-4 rounded-full ${baseRiskScore > 70 ? 'bg-red-500' : baseRiskScore > 40 ? 'bg-yellow-500' : 'bg-green-500'}`}
            style={{ width: `${baseRiskScore}%` }}
          />
        </div>
        <p className={`mt-2 text-sm ${baseRiskScore > 70 ? 'text-red-400' : baseRiskScore > 40 ? 'text-yellow-400' : 'text-green-400'}`}>
          Based on the provided information, this application is considered {baseRiskScore > 70 ? 'high risk' : baseRiskScore > 40 ? 'medium risk' : 'low risk'}.
        </p>
      </div>

      {/* Report Summary Table */}
      <div className="rounded-xl border border-slate-700 bg-slate-900/50 overflow-hidden">
        <div className="bg-gradient-to-r from-orange-900/40 to-slate-900 px-6 py-4 border-b border-slate-700">
          <h4 className="text-lg font-bold text-orange-400">Report Summary</h4>
        </div>
        <div className="divide-y divide-slate-700">
          <div className="grid grid-cols-12 p-4">
            <div className="col-span-3 font-semibold text-slate-300">Application Name</div>
            <div className="col-span-9 text-white">{appName}</div>
          </div>
          <div className="grid grid-cols-12 p-4">
            <div className="col-span-3 font-semibold text-slate-300">Application Description</div>
            <div className="col-span-9 text-slate-300 text-sm leading-relaxed">{appDesc}</div>
          </div>
          <div className="grid grid-cols-12 p-4">
            <div className="col-span-3 font-semibold text-slate-300">Data being shared</div>
            <div className="col-span-9">
              <p className="text-blue-400 text-sm mb-2 font-medium">{sharedDataSummary}</p>
              <p className="text-slate-400 text-xs">
                Prompt Data (user inputs and queries): Processed by LLM providers for response generation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Observations Table */}
      <div className="mt-8">
        <div className="rounded-xl border border-slate-700 bg-slate-900/50 overflow-hidden">
          <div className="bg-gradient-to-r from-orange-900/40 to-slate-900 px-6 py-4 border-b border-slate-700">
            <h4 className="text-lg font-bold text-orange-400">Detailed Observations Based on the Analysis</h4>
          </div>

          <div className="p-4 text-sm text-slate-300">
            Higher scores indicate more risk. Ensure mitigation measures are implemented for high-risk areas.
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-600 bg-slate-800/50">
                  <th className="p-4 text-orange-400 font-semibold w-10">#</th>
                  <th className="p-4 text-orange-400 font-semibold w-1/6">Risk Description</th>
                  <th className="p-4 text-orange-400 font-semibold w-1/5">Observation</th>
                  <th className="p-4 text-orange-400 font-semibold w-1/5">Impact</th>
                  <th className="p-4 text-orange-400 font-semibold w-1/6">Category</th>
                  <th className="p-4 text-orange-400 font-semibold w-20">Rating</th>
                  <th className="p-4 text-orange-400 font-semibold">Recommendations</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {/* First two static rows */}
                {staticObservations.map((obs, index) => (
                  <tr key={obs.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 text-slate-300 align-top">{index + 1}</td>
                    <td className="p-4 text-white font-medium align-top">{obs.riskDescription}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{obs.observation}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{obs.impact}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{obs.category}</td>
                    <td className="p-4 align-top">
                      <span className={`${obs.rating === 'High' ? 'text-red-400' : 'text-green-400'} font-bold`}>
                        {obs.rating}
                      </span>
                    </td>
                    <td className="p-4 text-slate-300 text-sm align-top">{obs.recommendation}</td>
                  </tr>
                ))}

                {/* Conditional third row based on AI scenario */}
                {aiScenario && (
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 text-slate-300 align-top">3</td>
                    <td className="p-4 text-white font-medium align-top">{aiScenario.riskDescription}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{aiScenario.observation}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{aiScenario.impact}</td>
                    <td className="p-4 text-slate-300 text-sm align-top">{aiScenario.category}</td>
                    <td className="p-4 align-top">
                      <span className={`${aiScenario.rating === 'High' ? 'text-red-400' : 'text-green-400'} font-bold`}>
                        {aiScenario.rating}
                      </span>
                    </td>
                    <td className="p-4 text-slate-300 text-sm align-top">{aiScenario.recommendation}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Vulnerable Components Table */}
      <div className="mt-8">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <h4 className="text-lg font-medium text-white">Vulnerable Components Identified</h4>
        </div>
        <div className="border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-800/50">
              <tr className="text-left">
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Severity</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Component</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Version</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Identifier</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {staticVulnerabilities.map((vuln) => (
                <tr key={vuln.id} className="bg-slate-800/20">
                  <td className="px-4 py-3"><RiskChip label={vuln.severity} size="small" /></td>
                  <td className="px-4 py-3 text-sm text-white">{vuln.component}</td>
                  <td className="px-4 py-3 text-sm text-slate-300">{vuln.version}</td>
                  <td className="px-4 py-3 text-sm text-slate-300">{vuln.cve}</td>
                  <td className="px-4 py-3 text-sm text-slate-300">{vuln.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* OSRA Risks Table */}
      <div className="mt-8">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-5 h-5 text-blue-400" />
          <h4 className="text-lg font-medium text-white">OSRA Risks</h4>
        </div>
        <div className="border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-800/50">
              <tr className="text-left">
                <th className="px-4 py-3 text-sm font-medium text-slate-300">SoT Risk</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Example in Context</th>
                <th className="px-4 py-3 text-sm font-medium text-slate-300">Suggested Mitigation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {staticMitreSoTRisks.map((risk) => (
                <tr key={risk.id} className="bg-slate-800/20">
                  <td className="px-4 py-3 text-sm font-medium text-white">{risk.risk}</td>
                  <td className="px-4 py-3 text-sm text-slate-300">{risk.example}</td>
                  <td className="px-4 py-3 text-sm text-slate-300">{risk.mitigation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Suggested Mitigations */}
      <div className="mt-8">
        <div className="flex items-center gap-2 mb-4">
          <CheckCircle2 className="w-5 h-5 text-green-400" />
          <h4 className="text-lg font-medium text-white">Suggested Mitigations</h4>
        </div>
        <div className="border border-slate-700 rounded-lg divide-y divide-slate-700">
          {staticMitigations.map((item) => (
            <div key={item.id} className="p-4 bg-slate-800/20">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                <div>
                  <h5 className="font-medium text-white mb-1">{item.recommendation}</h5>
                  <p className="text-sm text-slate-300">{item.details}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// --- Assessment List Sidebar ---
const AssessmentList = ({
  assessments,
  selectedAssessment,
  handleAssessmentSelect,
  handleDeleteAssessment,
  handleEditAssessment,
  handleNewAssessment
}) => {
  return (
    <div className="w-72 bg-slate-900 border-r border-slate-700 h-full overflow-y-auto">
      <div className="p-4 flex items-center justify-between border-b border-slate-700">
        <h3 className="text-lg font-semibold text-white">Previous Assessments</h3>
        <button onClick={handleNewAssessment} className="p-1.5 hover:bg-slate-800 rounded-lg transition-colors">
          <Plus className="w-5 h-5 text-blue-400" />
        </button>
      </div>
      <div className="p-2">
        {assessments.length > 0 ? assessments.map((assessment) => {
          const riskLevel = assessment.risk_score > 70 ? 'High' : assessment.risk_score > 40 ? 'Medium' : 'Low';
          const isSelected = selectedAssessment?.id === assessment.id;
          return (
            <div key={assessment.id} onClick={() => handleAssessmentSelect(assessment)} className={`p-3 mb-2 rounded-lg cursor-pointer transition-colors ${isSelected ? 'bg-blue-500/20 border border-blue-500/30' : 'hover:bg-slate-800/50'}`}>
              <div className="flex items-start gap-3">
                <BarChart3 className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-medium text-white truncate mb-1">{assessment.application_name || 'Untitled'}</h4>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-slate-400">{new Date(assessment.created_at).toLocaleDateString()}</span>
                    <RiskChip label={riskLevel} size="small" />
                  </div>
                  <div className="flex gap-1">
                    <button onClick={(e) => handleEditAssessment(assessment, e)} className="p-1 hover:bg-slate-700 rounded transition-colors"><Edit className="w-3.5 h-3.5 text-slate-400" /></button>
                    <button onClick={(e) => handleDeleteAssessment(assessment.id, e)} className="p-1 hover:bg-slate-700 rounded transition-colors"><Trash2 className="w-3.5 h-3.5 text-slate-400" /></button>
                  </div>
                </div>
              </div>
            </div>
          );
        }) : <div className="p-4 text-center text-slate-400 text-sm">No assessments yet</div>}
      </div>
    </div>
  );
};

// --- Main Component ---
const RiskAssessmentPage = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const [assessments, setAssessments] = useState([
    { id: 1, application_name: 'Data Miner', risk_score: 45, created_at: new Date().toISOString() }
  ]);
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  const [formData, setFormData] = useState({
    application_name: '', business_logic: '', application_type: '', platforms: '', frontend: '', backend: '', database: '',
    tech_stack_file: null, sow_proposal_file: null, architecture: '', hosting: '', sensitive_data: '', third_party_integrations: '',
    error_handling: '', user_input_handling: '', data_security: '', legacy_dependencies: '', monitoring: '',
    ai_data_types: '', ai_data_structure: '', ai_data_sensitivity: '', ai_third_party_sharing: '', ai_shared_data_details: ''
  });

  const steps = [
    { label: 'Application Information', icon: FileText },
    { label: 'Architecture & Hosting', icon: Cloud },
    { label: 'Risk & Security', icon: Shield },
    { label: 'AI Risk Assessment', icon: Brain },
    { label: 'Risk Analysis', icon: BarChart3 }
  ];

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleFileChange = (e) => {
    const { name, files } = e.target;
    if (files && files.length > 0) setFormData(prev => ({ ...prev, [name]: files[0] }));
  };

  const handleRemoveFile = (name) => setFormData(prev => ({ ...prev, [name]: null }));
  const handleTechStackChange = (category, value) => setFormData(prev => ({ ...prev, [category]: value }));

  const handleSubmitAssessment = async () => {
    setIsSubmitting(true);
    setTimeout(() => {
      setIsEditing(false);
      setActiveStep(4);
      setIsSubmitting(false);
    }, 1000);
  };

  const handleNext = () => {
    if (activeStep === 3) handleSubmitAssessment();
    else if (activeStep < steps.length - 1) setActiveStep(prev => prev + 1);
  };

  const handleBack = () => setActiveStep(prev => prev - 1);

  const handleAssessmentSelect = (assessment) => {
    setSelectedAssessment(assessment);
    setFormData({ ...formData, ...assessment });
    setIsEditing(false);
    setActiveStep(4);
    setMobileDrawerOpen(false);
  };

  const handleDeleteAssessment = (id, e) => {
    if (e) e.stopPropagation();
    if (window.confirm('Delete this assessment?')) setAssessments(prev => prev.filter(a => a.id !== id));
  };

  const handleEditAssessment = (assessment, e) => {
    if (e) e.stopPropagation();
    setSelectedAssessment(assessment);
    setFormData({ ...formData, ...assessment });
    setIsEditing(true);
    setActiveStep(0);
    setMobileDrawerOpen(false);
  };

  const handleNewAssessment = () => {
    setSelectedAssessment(null);
    setFormData({
      application_name: '', business_logic: '', application_type: '', platforms: '', frontend: '', backend: '', database: '',
      tech_stack_file: null, sow_proposal_file: null, architecture: '', hosting: '', sensitive_data: '', third_party_integrations: '',
      error_handling: '', user_input_handling: '', data_security: '', legacy_dependencies: '', monitoring: '',
      ai_data_types: '', ai_data_structure: '', ai_data_sensitivity: '', ai_third_party_sharing: '', ai_shared_data_details: ''
    });
    setIsEditing(false);
    setActiveStep(0);
    setMobileDrawerOpen(false);
  };

  const getStepContent = (step) => {
    switch (step) {
      case 0: return <AppInformation formData={formData} handleInputChange={handleInputChange} handleTechStackChange={handleTechStackChange} handleFileChange={handleFileChange} handleRemoveFile={handleRemoveFile} />;
      case 1: return <ArchitectureHosting formData={formData} handleInputChange={handleInputChange} />;
      case 2: return <RiskSecurity formData={formData} handleInputChange={handleInputChange} />;
      case 3: return <AIRiskAssessment formData={formData} handleInputChange={handleInputChange} />;
      case 4: return <StaticRiskAnalysis formData={formData} />;
      default: return 'Unknown step';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <div className="max-w-[1920px] mx-auto p-6">
        <div className="flex items-center justify-between mb-6">
          <button className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors"><ArrowLeft className="w-5 h-5" /><span>Back to Home</span></button>
          <button onClick={() => setMobileDrawerOpen(!mobileDrawerOpen)} className="md:hidden px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm">Assessments</button>
        </div>
        <h1 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent mb-3">Architecture Risk Assessment Lab</h1>
        <p className="text-slate-400 text-lg mb-8">Comprehensive AI-powered risk assessment tools</p>
        <div className="flex gap-6 bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 overflow-hidden min-h-[600px]">
          <div className="hidden md:block">
            <AssessmentList assessments={assessments} selectedAssessment={selectedAssessment} handleAssessmentSelect={handleAssessmentSelect} handleDeleteAssessment={handleDeleteAssessment} handleEditAssessment={handleEditAssessment} handleNewAssessment={handleNewAssessment} />
          </div>
          {mobileDrawerOpen && (
            <div className="fixed inset-0 z-50 md:hidden">
              <div className="absolute inset-0 bg-black/50" onClick={() => setMobileDrawerOpen(false)} />
              <div className="absolute left-0 top-0 bottom-0 w-72"><AssessmentList assessments={assessments} selectedAssessment={selectedAssessment} handleAssessmentSelect={handleAssessmentSelect} handleDeleteAssessment={handleDeleteAssessment} handleEditAssessment={handleEditAssessment} handleNewAssessment={handleNewAssessment} /></div>
            </div>
          )}
          <div className="flex-1 flex flex-col min-w-0">
            <div className="p-6 border-b border-slate-800">
              <div className="hidden md:flex items-center justify-between">
                {steps.map((step, index) => {
                  const Icon = step.icon;
                  const isActive = activeStep === index;
                  const isCompleted = activeStep > index;
                  return (
                    <React.Fragment key={step.label}>
                      <div className="flex items-center gap-3">
                        <div className={`flex items-center justify-center w-10 h-10 rounded-full border-2 transition-colors ${isActive ? 'border-blue-500 bg-blue-500/20 text-blue-400' : isCompleted ? 'border-green-500 bg-green-500/20 text-green-400' : 'border-slate-700 text-slate-500'}`}><Icon className="w-5 h-5" /></div>
                        <span className={`text-sm font-medium ${isActive ? 'text-white' : 'text-slate-400'}`}>{step.label}</span>
                      </div>
                      {index < steps.length - 1 && <div className={`flex-1 h-0.5 mx-4 ${isCompleted ? 'bg-green-500' : 'bg-slate-700'}`} />}
                    </React.Fragment>
                  );
                })}
              </div>
              <div className="md:hidden space-y-3">
                <div className="flex items-center gap-3 text-white"><span>{steps[activeStep].label}</span></div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-6">{getStepContent(activeStep)}</div>
            <div className="p-6 border-t border-slate-800 flex items-center justify-between">
              <button onClick={handleBack} disabled={activeStep === 0} className="px-6 py-2.5 border border-slate-700 rounded-lg text-white hover:bg-slate-800 disabled:opacity-50 transition-colors">Back</button>
              {activeStep < steps.length - 1 ? (
                <button onClick={handleNext} disabled={isSubmitting} className="px-6 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white font-medium transition-all disabled:opacity-50">{activeStep === 3 ? 'Submit Assessment' : 'Next'}</button>
              ) : (
                <button onClick={handleNewAssessment} className="px-6 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white font-medium transition-all">Start New Assessment</button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RiskAssessmentPage;