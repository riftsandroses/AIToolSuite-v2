import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  RefreshCw,
  Download,
  Eye,
  Play,
  CheckCircle,
  Clock,
  AlertCircle,
  FileText,
  Shield,
  TreePine,
  Activity,
  Target
} from 'lucide-react';
import { getAuthCookies } from '../../api/auth';
import MermaidDiagram from '../../Components/ThreatModel/MermaidDiagram';

const token = getAuthCookies().accessToken

const apiCall = async (endpoint, method = 'GET', data = null) => {
  const baseURL = process.env.REACT_APP_API_BASE_URL || '';

  const config = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
  };

  if (data && method !== 'GET') {
    config.body = JSON.stringify(data);
  }

  try {
    const response = await fetch(`${baseURL}/api/v1/threat-model${endpoint}`, config);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Handle different content types
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    } else {
      return await response.text();
    }
  } catch (error) {
    console.error(`API call failed for ${endpoint}:`, error);
    throw error;
  }
};

const ThreatModelAssessment = () => {
  const [threatModelId, setThreatModelId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scanDetails, setScanDetails] = useState(null);
  const [history, setHistory] = useState([]);
  const [assessmentStatuses, setAssessmentStatuses] = useState({});
  const [activeTab, setActiveTab] = useState('overview');
  const [reports, setReports] = useState({});
  const [generating, setGenerating] = useState({});

  useEffect(() => {
    // Extract ID from URL
    const extractIdFromUrl = () => {
      const urlParams = new URLSearchParams(window.location.search);
      const id = urlParams.get('id');
      if (id) {
        setThreatModelId(parseInt(id));
      } else {
        // Fallback: extract from pathname if using route params
        const pathParts = window.location.pathname.split('/');
        const idFromPath = pathParts[pathParts.length - 1];
        if (idFromPath && !isNaN(idFromPath)) {
          setThreatModelId(parseInt(idFromPath));
        }
      }
    };

    extractIdFromUrl();
  }, []);

  useEffect(() => {
    if (threatModelId) {
      loadInitialData();
    }
  }, [threatModelId]);

  const loadInitialData = async () => {
    setLoading(true);
    setError(null);

    try {
      // Load scan details and history
      const [statusData, historyData] = await Promise.all([
        apiCall(`/status/${threatModelId}/`),
        apiCall('/history/')
      ]);

      setScanDetails(statusData);
      setHistory(historyData);

      // If scan is completed, load assessment statuses
      if (statusData.status === 'completed') {
        await loadAssessmentStatuses();
      }
    } catch (error) {
      console.error('Error loading initial data:', error);
      setError('Failed to load assessment data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const loadAssessmentStatuses = async () => {
    try {
      const [strideStatus, dreadStatus, pastaStatus, attackTreeStatus] = await Promise.all([
        apiCall(`/analysis-status/${threatModelId}/`),
        apiCall(`/dread-status/${threatModelId}/`),
        apiCall(`/pasta-status/${threatModelId}/`),
        apiCall(`/attack-tree-status/${threatModelId}/`)
      ]);

      setAssessmentStatuses({
        stride: strideStatus,
        dread: dreadStatus,
        pasta: pastaStatus,
        attackTree: attackTreeStatus
      });
    } catch (error) {
      console.error('Error loading assessment statuses:', error);
      setError('Failed to load assessment statuses.');
    }
  };

  const handleGenerate = async (assessmentType) => {
    setGenerating(prev => ({ ...prev, [assessmentType]: true }));

    try {
      let endpoint = '';
      switch (assessmentType) {
        case 'stride':
          endpoint = `/analyze/${threatModelId}/`;
          break;
        case 'dread':
          endpoint = `/dread-assess/${threatModelId}/`;
          break;
        case 'pasta':
          endpoint = `/pasta-assess/${threatModelId}/`;
          break;
        case 'attackTree':
          endpoint = `/attack-tree/${threatModelId}/`;
          break;
      }

      await apiCall(endpoint, 'POST');

      // Reload statuses after generation
      setTimeout(() => {
        loadAssessmentStatuses();
      }, 2000); // Wait 2 seconds for processing to start

    } catch (error) {
      console.error(`Error generating ${assessmentType}:`, error);
      setError(`Failed to generate ${assessmentType} assessment. Please try again.`);
    } finally {
      setGenerating(prev => ({ ...prev, [assessmentType]: false }));
    }
  };

  const handleView = async (reportType) => {
    try {
      let endpoint = '';
      switch (reportType) {
        case 'stride':
          endpoint = `/report/${threatModelId}/?format=json`;
          break;
        case 'dread':
          endpoint = `/dread-report/${threatModelId}/`;
          break;
        case 'pasta':
          endpoint = `/pasta-assess/${threatModelId}/`;
          break;
        case 'attackTree':
          endpoint = `/attack-tree/${threatModelId}/`;
          break;
      }

      const data = await apiCall(endpoint);
      setReports(prev => ({ ...prev, [reportType]: data }));
      setActiveTab(reportType);
    } catch (error) {
      console.error(`Error loading ${reportType} report:`, error);
      setError(`Failed to load ${reportType} report. Please try again.`);
    }
  };

  const handleDownload = async (reportType) => {
    try {
      let endpoint = '';
      let filename = '';

      switch (reportType) {
        case 'stride':
          endpoint = `/report/${threatModelId}/`;
          filename = `stride-report-${threatModelId}.csv`;
          break;
        case 'dread':
          endpoint = `/dread-report/${threatModelId}/`;
          filename = `dread-report-${threatModelId}.json`;
          break;
        case 'pasta':
          // Assuming PASTA generates a PDF
          endpoint = `/pasta-assess/${threatModelId}/export`;
          filename = `pasta-report-${threatModelId}.pdf`;
          break;
        case 'attackTree':
          endpoint = `/attack-tree/${threatModelId}/export`;
          filename = `attack-tree-${threatModelId}.pdf`;
          break;
      }

      const response = await fetch(`${process.env.REACT_APP_API_BASE_URL}/api/v1/threat-model${endpoint}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('Download failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error(`Error downloading ${reportType}:`, error);
      setError(`Failed to download ${reportType} report. Please try again.`);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Completed':
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'Processing':
        return <Clock className="w-5 h-5 text-yellow-400 animate-pulse" />;
      case 'Not Started':
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const AssessmentCard = ({ title, icon: Icon, status, onGenerate, onView, onDownload, disabled = false, isGenerating = false }) => (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Icon className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg font-semibold text-white">{title}</h3>
        </div>
        {isGenerating ? (
          <RefreshCw className="w-5 h-5 text-yellow-400 animate-spin" />
        ) : (
          getStatusIcon(status)
        )}
      </div>

      <div className="flex space-x-2">
        {status !== 'Completed' && !disabled && (
          <button
            onClick={onGenerate}
            disabled={isGenerating}
            className="flex items-center space-x-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-md text-sm font-medium transition-colors"
          >
            {isGenerating ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span>{isGenerating ? 'Generating...' : 'Generate'}</span>
          </button>
        )}

        {status === 'Completed' && (
          <>
            <button
              onClick={onView}
              className="flex items-center space-x-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-md text-sm font-medium transition-colors"
            >
              <Eye className="w-4 h-4" />
              <span>View</span>
            </button>
            <button
              onClick={onDownload}
              className="flex items-center space-x-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-md text-sm font-medium transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Download</span>
            </button>
          </>
        )}

        {disabled && (
          <p className="text-sm text-gray-400 py-2">
            Complete STRIDE analysis first
          </p>
        )}
      </div>
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'stride':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">STRIDE Analysis Report</h3>
              <div className="text-sm text-gray-400">
                Total Threats: {reports.stride?.executive_summary?.total_threats || 0}
              </div>
            </div>

            {/* Executive Summary */}
            {reports.stride?.executive_summary && (
              <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 mb-6">
                <h4 className="text-lg font-semibold text-white mb-3">Executive Summary</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="bg-gray-900 rounded p-3">
                    <div className="text-2xl font-bold text-white">{reports.stride.executive_summary.total_threats}</div>
                    <div className="text-sm text-gray-400">Total Threats</div>
                  </div>
                  <div className="bg-gray-900 rounded p-3">
                    <div className="text-2xl font-bold text-red-400">{reports.stride.executive_summary.critical_threats}</div>
                    <div className="text-sm text-gray-400">Critical Threats</div>
                  </div>
                  <div className="bg-gray-900 rounded p-3">
                    <div className="text-2xl font-bold text-blue-400">
                      {Math.round((reports.stride.confidence_metrics?.overall_confidence || 0) * 100)}%
                    </div>
                    <div className="text-sm text-gray-400">Confidence</div>
                  </div>
                </div>

                {reports.stride.executive_summary.top_recommendations && (
                  <div className="mb-4">
                    <h5 className="font-semibold text-white mb-2">Top Recommendations</h5>
                    <ul className="space-y-1">
                      {reports.stride.executive_summary.top_recommendations.map((rec, i) => (
                        <li key={i} className="text-gray-300 text-sm flex items-start">
                          <span className="w-2 h-2 bg-green-400 rounded-full mt-2 mr-3 flex-shrink-0"></span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {reports.stride.executive_summary.high_risk_areas && (
                  <div>
                    <h5 className="font-semibold text-white mb-2">High Risk Areas</h5>
                    <div className="flex flex-wrap gap-2">
                      {reports.stride.executive_summary.high_risk_areas.map((area, i) => (
                        <span key={i} className="px-2 py-1 bg-red-600 text-white text-xs rounded">
                          {area}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Threat Model Details */}
            {reports.stride?.threat_model?.map((threat, index) => (
              <div key={index} className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded font-mono">
                      {threat.threat_id}
                    </span>
                    <span className="px-2 py-1 bg-purple-600 text-white text-xs rounded">
                      {threat.threat_type}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 text-xs rounded ${threat.likelihood === 'High' ? 'bg-red-600 text-white' :
                      threat.likelihood === 'Medium' ? 'bg-yellow-600 text-white' :
                        'bg-green-600 text-white'
                      }`}>
                      {threat.likelihood} Likelihood
                    </span>
                    <span className={`px-2 py-1 text-xs rounded ${threat.potential_impact?.includes('High') ? 'bg-red-600 text-white' :
                      threat.potential_impact?.includes('Medium') ? 'bg-yellow-600 text-white' :
                        'bg-green-600 text-white'
                      }`}>
                      High Impact
                    </span>
                  </div>
                </div>

                <div className="mb-3">
                  <h5 className="font-semibold text-white mb-2">Scenario</h5>
                  <p className="text-gray-300 text-sm">{threat.scenario}</p>
                </div>

                <div className="mb-3">
                  <h5 className="font-semibold text-white mb-2">Attack Vector</h5>
                  <p className="text-gray-300 text-sm">{threat.attack_vector}</p>
                </div>

                {threat.affected_components && threat.affected_components.length > 0 && (
                  <div className="mb-3">
                    <h5 className="font-semibold text-white mb-2">Affected Components</h5>
                    <div className="flex flex-wrap gap-2">
                      {threat.affected_components.map((component, i) => (
                        <span key={i} className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded">
                          {component}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mb-3">
                  <h5 className="font-semibold text-white mb-2">Potential Impact</h5>
                  <p className="text-gray-300 text-sm">{threat.potential_impact}</p>
                </div>

                <div>
                  <h5 className="font-semibold text-white mb-2">Mitigation Suggestion</h5>
                  <p className="text-gray-300 text-sm">{threat.mitigation_suggestion}</p>
                </div>
              </div>
            ))}

            {/* Analysis Metadata */}
            {reports.stride?.analysis_metadata && (
              <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                <h4 className="text-lg font-semibold text-white mb-3">Analysis Details</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Model Used:</span>
                    <span className="ml-2 text-white">{reports.stride.analysis_metadata.model_used}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Documents:</span>
                    <span className="ml-2 text-white">{reports.stride.analysis_metadata.unique_documents}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Chunks Analyzed:</span>
                    <span className="ml-2 text-white">{reports.stride.analysis_metadata.chunks_analyzed}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Generated:</span>
                    <span className="ml-2 text-white">
                      {new Date(reports.stride.analysis_metadata.generated_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                {reports.stride.context_quality && (
                  <div className="mt-4">
                    <h5 className="font-semibold text-white mb-2">Context Quality Metrics</h5>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Technical Depth:</span>
                        <span className="ml-2 text-white">
                          {Math.round((reports.stride.context_quality.technical_depth || 0) * 100)}%
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Security Context:</span>
                        <span className="ml-2 text-white">
                          {Math.round((reports.stride.context_quality.security_context || 0) * 100)}%
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Document Coverage:</span>
                        <span className="ml-2 text-white">
                          {Math.round((reports.stride.context_quality.document_coverage || 0) * 100)}%
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Architecture Clarity:</span>
                        <span className="ml-2 text-white">
                          {Math.round((reports.stride.context_quality.architecture_clarity || 0) * 100)}%
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {reports.stride?.improvement_suggestions && reports.stride.improvement_suggestions.length > 0 && (
              <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                <h4 className="text-lg font-semibold text-white mb-3">Improvement Suggestions</h4>
                <ul className="space-y-2">
                  {reports.stride.improvement_suggestions.map((suggestion, i) => (
                    <li key={i} className="text-gray-300 text-sm flex items-start">
                      <span className="w-2 h-2 bg-yellow-400 rounded-full mt-2 mr-3 flex-shrink-0"></span>
                      {suggestion}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        );

      case 'dread':
        return (
          <div className="space-y-6">
            <h3 className="text-xl font-semibold text-white">DREAD Risk Assessment</h3>
            {reports.dread?.dread_assessment?.["Risk Assessment"]?.map((risk, index) => (
              <div key={index} className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="px-2 py-1 bg-purple-600 text-white text-xs rounded">{risk["Threat Type"]}</span>
                  <div className="flex space-x-2">
                    <span className="text-sm text-gray-400">Affected Users: {risk["Affected Users"]}</span>
                  </div>
                </div>
                <p className="text-gray-300 mb-3">{risk.Scenario}</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Exploitability:</span>
                    <span className="ml-2 text-white">{risk.Exploitability}/10</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Discoverability:</span>
                    <span className="ml-2 text-white">{risk.Discoverability}/10</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Reproducibility:</span>
                    <span className="ml-2 text-white">{risk.Reproducibility}/10</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Damage Potential:</span>
                    <span className="ml-2 text-white">{risk["Damage Potential"]}/10</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        );

      case 'pasta':
        return (
          <div className="space-y-6">
            <h3 className="text-xl font-semibold text-white">PASTA Assessment</h3>

            {reports.pasta?.pasta_assessment_data?.threat_model?.threat_model?.map((model, index) => (
              <div key={index} className="space-y-4">
                <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                  <h4 className="text-lg font-semibold text-white mb-3">Identified Threats</h4>
                  <ul className="space-y-2">
                    {model.Threats?.map((threat, i) => (
                      <li key={i} className="text-gray-300 flex items-start">
                        <span className="w-2 h-2 bg-red-400 rounded-full mt-2 mr-3 flex-shrink-0"></span>
                        {threat}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                  <h4 className="text-lg font-semibold text-white mb-3">Recommended Mitigations</h4>
                  <ul className="space-y-2">
                    {model.Mitigations?.map((mitigation, i) => (
                      <li key={i} className="text-gray-300 flex items-start">
                        <span className="w-2 h-2 bg-green-400 rounded-full mt-2 mr-3 flex-shrink-0"></span>
                        {mitigation}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}

            {reports.pasta?.pasta_assessment_data?.security_controls?.control_matrix && (
              <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
                <h4 className="text-lg font-semibold text-white mb-3">Security Controls</h4>
                {reports.pasta.pasta_assessment_data.security_controls.control_matrix.map((control, index) => (
                  <div key={index} className="mb-4 last:mb-0">
                    <div className="flex items-center justify-between mb-2">
                      <span className="px-2 py-1 bg-orange-600 text-white text-xs rounded">{control["CCM Control ID"]}</span>
                      <div className="text-xs text-gray-400">
                        ISO: {control["ISO 27001 reference"]} | NIST: {control["NIST 800-53 reference"]}
                      </div>
                    </div>
                    <p className="text-gray-300 text-sm mb-2">{control["Control Description"]}</p>
                    <div className="text-xs text-gray-400">
                      <strong>Key Questions:</strong>
                      <ul className="mt-1 ml-4">
                        {control.Questionnaires?.map((question, i) => (
                          <li key={i}>• {question}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case 'attackTree':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-semibold text-white">Attack Tree Visualization</h3>
              {reports.attackTree?.threat_model_id && (
                <div className="text-sm text-gray-400">
                  Threat Model ID: {reports.attackTree.threat_model_id}
                </div>
              )}
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-white mb-2">Attack Tree Diagram</h4>
                <p className="text-gray-400 text-sm mb-4">
                  This diagram visualizes potential attack paths and vectors targeting your application.
                  Each path shows how an attacker might progress from initial access to their ultimate goal.
                </p>
              </div>

              {reports.attackTree?.attack_tree_mermaid ? (
                <MermaidDiagram
                  chart={reports.attackTree.attack_tree_mermaid}
                  id={`attack-tree-${reports.attackTree.threat_model_id || 'default'}`}
                />
              ) : (
                <div className="bg-gray-900 rounded p-8 text-center">
                  <TreePine className="w-12 h-12 text-gray-500 mx-auto mb-3" />
                  <p className="text-gray-400">No attack tree data available</p>
                </div>
              )}

              <div className="mt-4 p-3 bg-gray-900 rounded">
                <h5 className="font-semibold text-white mb-2">How to Read This Diagram</h5>
                <ul className="text-sm text-gray-300 space-y-1">
                  <li>• <strong>Root Node:</strong> The attacker's ultimate objective</li>
                  <li>• <strong>Intermediate Nodes:</strong> Steps or methods to achieve the goal</li>
                  <li>• <strong>Leaf Nodes:</strong> Specific attack techniques (with MITRE ATT&CK IDs where applicable)</li>
                  <li>• <strong>Paths:</strong> Different routes an attacker might take</li>
                </ul>
              </div>

              {reports.attackTree?.attack_tree_mermaid && (
                <div className="mt-4 flex justify-end">
                  <button
                    onClick={() => {
                      const mermaidCode = reports.attackTree.attack_tree_mermaid;
                      navigator.clipboard.writeText(mermaidCode);
                      // You could add a toast notification here
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors flex items-center space-x-2"
                  >
                    <FileText className="w-4 h-4" />
                    <span>Copy Mermaid Code</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        );

      default:
        return (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Assessment Overview</h3>
              <p className="text-gray-300 mb-4">
                This threat model assessment provides comprehensive security analysis using industry-standard methodologies.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-900 rounded p-4">
                  <h4 className="font-semibold text-white mb-2">Application</h4>
                  <p className="text-gray-300">{scanDetails?.app_name || 'N/A'}</p>
                </div>
                <div className="bg-gray-900 rounded p-4">
                  <h4 className="font-semibold text-white mb-2">Status</h4>
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(scanDetails?.status)}
                    <span className="text-gray-300 capitalize">{scanDetails?.status}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <h3 className="text-xl font-semibold text-white mb-4">Scan History</h3>
              <div className="space-y-3">
                {history.slice(0, 5).map((item, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-900 rounded">
                    <div>
                      <p className="text-white font-medium">{item.action}</p>
                      <p className="text-gray-400 text-sm">{item.threat_model}</p>
                      {item.details?.files_uploaded && (
                        <div className="text-xs text-gray-500 mt-1">
                          Files: {item.details.files_uploaded.join(', ')}
                        </div>
                      )}
                    </div>
                    <span className="text-gray-400 text-sm">
                      {formatDate(item.timestamp)}
                    </span>
                  </div>
                ))}
                {history.length === 0 && (
                  <p className="text-gray-400 text-center py-4">No history available</p>
                )}
              </div>
            </div>
          </div>
        );
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 text-blue-400 animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading threat model assessment...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-4" />
          <p className="text-gray-400 mb-4">{error}</p>
          <button
            onClick={loadInitialData}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!threatModelId) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-4" />
          <p className="text-gray-400">No threat model ID found in URL</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => window.history.back()}
              className="flex items-center space-x-2 text-blue-400 hover:text-blue-300 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span>Back to Home</span>
            </button>
            <div className="text-gray-400">|</div>
            <h1 className="text-2xl font-bold text-blue-300">AI Threat Model Assessment</h1>
          </div>
          <button
            onClick={loadInitialData}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
        </div>
        <p className="text-gray-400 mt-2">Comprehensive AI-powered threat modeling and security assessment tools</p>
      </div>

      <div className="p-6">
        {/* Scan Details Card */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-white">Scan Details</h2>
            <div className="flex items-center space-x-2">
              {getStatusIcon(scanDetails?.status)}
              <span className="text-gray-300 capitalize">{scanDetails?.status}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-2">Threat Model ID</h3>
              <p className="text-white">{scanDetails?.threat_model_id || threatModelId}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-2">Application Name</h3>
              <p className="text-white">{scanDetails?.app_name || 'N/A'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-2">Processing Status</h3>
              <div className="flex items-center space-x-2">
                {getStatusIcon(scanDetails?.status)}
                <span className="text-white capitalize">{scanDetails?.status}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Assessment Cards */}
        {scanDetails?.status === 'completed' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            <AssessmentCard
              title="STRIDE"
              icon={Shield}
              status={assessmentStatuses.stride?.analysis_status}
              onGenerate={() => handleGenerate('stride')}
              onView={() => handleView('stride')}
              onDownload={() => handleDownload('stride')}
              isGenerating={generating.stride}
            />

            <AssessmentCard
              title="ATTACK TREE"
              icon={TreePine}
              status={assessmentStatuses.attackTree?.attack_tree_status}
              onGenerate={() => handleGenerate('attackTree')}
              onView={() => handleView('attackTree')}
              onDownload={() => handleDownload('attackTree')}
              isGenerating={generating.attackTree}
            />

            <AssessmentCard
              title="DREAD"
              icon={Activity}
              status={assessmentStatuses.dread?.dread_status}
              onGenerate={() => handleGenerate('dread')}
              onView={() => handleView('dread')}
              onDownload={() => handleDownload('dread')}
              disabled={assessmentStatuses.stride?.analysis_status !== 'Completed'}
              isGenerating={generating.dread}
            />

            <AssessmentCard
              title="PASTA"
              icon={Target}
              status={assessmentStatuses.pasta?.pasta_status}
              onGenerate={() => handleGenerate('pasta')}
              onView={() => handleView('pasta')}
              onDownload={() => handleDownload('pasta')}
              isGenerating={generating.pasta}
            />
          </div>
        )}

        {/* Tab Navigation */}
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="border-b border-gray-700">
            <nav className="flex space-x-8 px-6">
              {[
                { key: 'overview', label: 'Overview', icon: FileText },
                { key: 'stride', label: 'STRIDE Analysis', icon: Shield },
                { key: 'dread', label: 'DREAD Assessment', icon: Activity },
                { key: 'pasta', label: 'PASTA Report', icon: Target },
                { key: 'attackTree', label: 'Attack Tree', icon: TreePine }
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className={`py-4 px-2 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors ${activeTab === key
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                    }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{label}</span>
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {renderTabContent()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatModelAssessment;