import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Eye, Calendar, Users, Smartphone, Upload, Lock, User, FileText, Search, Shield, Server, Database } from 'lucide-react';
import { getAuthCookies } from '../../api/auth';
import { callBackend, formatDate } from '../../utils/helpers';

const ThreatModel = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    assessment_name: '',
    app_name: '',
    client_name: '',
    description: '',
    authentication_method: '',
    handles_sensitive_data: '',
    data_classification: '',
    deployment_environment: '',
    compliance_requirements: '',
    user_types: '',
    third_party_integrations: '',
    files: [],
    technology_stack: '',
    deployment_environment_detail: '',
    critical_assets: ''
  });
  const baseURL = process.env.REACT_APP_API_BASE_URL;

  const [historicalAssessments, setHistoricalAssessments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [alert, setAlert] = useState({ show: false, type: '', message: '' });

  useEffect(() => {
    fetchHistoricalAssessments();
  }, []);

  const fetchHistoricalAssessments = async () => {
    setLoading(true);
    try {
      const response = await callBackend('/api/v1/threat-model/assessments/')
      if (response.ok) {
        const data = await response.json();
        setHistoricalAssessments(data.slice(0, 5));
      } else {
        console.error('Failed to fetch historical assessments');
      }
    } catch (error) {
      console.error('Error fetching historical assessments:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleFileUpload = (event) => {
    const newFiles = Array.from(event.target.files);
    const allowedExtensions = [
      ".pdf", ".docx", ".xls", ".xlsx", ".txt", ".png", ".jpg", ".jpeg"
    ];
    const validFiles = newFiles.filter(file => {
      const ext = "." + file.name.split(".").pop().toLowerCase();
      return allowedExtensions.includes(ext);
    });
    setFormData(prev => ({
      ...prev,
      files: [...prev.files, ...validFiles]
    }));
  };


  const removeFile = (indexToRemove) => {
    setFormData(prev => ({
      ...prev,
      files: prev.files.filter((_, index) => index !== indexToRemove)
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitLoading(true);

    try {
      const formDataToSend = new FormData();
      const dataToProcess = { ...formData };

      if (dataToProcess.technology_stack && typeof dataToProcess.technology_stack === 'string') {
        const techStackArray = dataToProcess.technology_stack
          .split(',')
          .map(item => item.trim())
          .filter(item => item !== '');
        dataToProcess.technology_stack = JSON.stringify(techStackArray);
      }

      Object.keys(dataToProcess).forEach(key => {
        if (key === 'files') {
          dataToProcess.files.forEach(file => {
            formDataToSend.append('files', file);
          });
        } else {
          formDataToSend.append(key, dataToProcess[key]);
        }
      });

      const token = getAuthCookies().accessToken;

      const response = await fetch(`${baseURL}/api/v1/threat-model/create-assessment/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formDataToSend
      });

      if (response.ok) {
        setAlert({
          show: true,
          type: 'success',
          message: 'Threat model assessment created successfully!'
        });
        setFormData({
          assessment_name: '',
          app_name: '',
          client_name: '',
          description: '',
          authentication_method: '',
          handles_sensitive_data: '',
          data_classification: '',
          deployment_environment: '',
          compliance_requirements: '',
          user_types: '',
          third_party_integrations: '',
          files: [],
          technology_stack: '',
          deployment_environment_detail: '',
          critical_assets: ''
        });

        const fileInput = document.getElementById('files-input');
        if (fileInput) fileInput.value = '';

        fetchHistoricalAssessments();
      } else {
        setAlert({
          show: true,
          type: 'error',
          message: 'Failed to create assessment. Please try again.'
        });
      }
    } catch (error) {
      setAlert({
        show: true,
        type: 'error',
        message: 'An error occurred. Please try again.'
      });
    } finally {
      setSubmitLoading(false);
      setTimeout(() => setAlert({ show: false, type: '', message: '' }), 3000);
    }
  };

  const handleAssessmentClick = (assessmentId) => {
    navigate(`/threat-model/${assessmentId}`);
  };

  const handleViewAllAssessments = () => {
    navigate('/threat-model/all');
  };

  const handleRefresh = () => {
    fetchHistoricalAssessments();
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto p-6">
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-blue-400 hover:underline flex items-center gap-2">
              <ArrowLeft size={20} />
              Back to Home
            </Link>
          </div>
          <button
            onClick={handleRefresh}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>

        <div className="mb-8">
          <h1 className="text-4xl font-bold text-blue-300 mb-2">AI Threat Model Assessment</h1>
          <p className="text-lg text-gray-400">
            Comprehensive AI-powered threat modeling and security assessment tools
          </p>
        </div>

        <div className="flex gap-6">
          <div className="w-80 bg-gray-800 rounded-lg">
            <div className="p-6 border-b border-gray-700">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                  <Shield size={20} />
                  Recent Assessments
                </h2>
              </div>
            </div>

            <div className="p-6">
              {loading ? (
                <div className="text-center py-8">
                  <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400 mb-4"></div>
                  <div className="text-gray-400">Loading assessments...</div>
                </div>
              ) : historicalAssessments.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <div className="text-lg mb-4">No assessments yet</div>
                  <div className="text-sm">Create your first assessment to get started</div>
                </div>
              ) : (
                <div className="space-y-3">
                  {historicalAssessments.map(assessment => (
                    <div
                      key={assessment.id}
                      className="p-4 rounded-lg cursor-pointer transition-colors bg-gray-700 hover:bg-gray-600 border border-gray-600 hover:border-gray-500"
                      onClick={() => handleAssessmentClick(assessment.id)}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                        <div className="font-medium text-white text-sm truncate">
                          {assessment.assessment_name}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-gray-300 mb-1">
                        <Users size={12} />
                        <span className="truncate">{assessment.client_name}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-gray-300 mb-2">
                        <Smartphone size={12} />
                        <span className="truncate">{assessment.app_name}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-xs text-gray-400">
                          <Calendar size={12} />
                          <span>{formatDate(assessment.created_at)}</span>
                        </div>
                        <div className="bg-blue-600 text-white px-2 py-1 rounded text-xs font-medium">
                          <Shield size={12} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-6 space-y-3">
                <button
                  onClick={handleViewAllAssessments}
                  className="w-full flex items-center justify-center gap-2 border border-blue-400 text-blue-400 py-3 rounded-lg hover:bg-blue-600 hover:text-white transition-colors font-medium"
                >
                  <Eye size={16} />
                  View All Assessments
                </button>
              </div>
            </div>
          </div>

          <div className="flex-1">
            <div className="bg-gray-800 rounded-lg">
              <div className="p-6 border-b border-gray-700">
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                  <Shield size={20} />
                  Create New Threat Model Assessment
                </h2>
              </div>

              <div className="p-6">
                {alert.show && (
                  <div className={`mb-6 p-4 rounded-lg border ${alert.type === 'error'
                    ? 'bg-red-900 border-red-600 text-red-200'
                    : 'bg-green-900 border-green-600 text-green-200'
                    }`}>
                    {alert.message}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
                  <div>
                    <label className="text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Shield size={16} />
                      Assessment Name
                    </label>
                    <input
                      type="text"
                      name="assessment_name"
                      value={formData.assessment_name}
                      onChange={handleInputChange}
                      placeholder="Enter assessment name"
                      required
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Smartphone size={16} />
                        Application Name
                      </label>
                      <input
                        type="text"
                        name="app_name"
                        value={formData.app_name}
                        onChange={handleInputChange}
                        placeholder="Enter application name"
                        required
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Users size={16} />
                        Client Name
                      </label>
                      <input
                        type="text"
                        name="client_name"
                        value={formData.client_name}
                        onChange={handleInputChange}
                        placeholder="Enter client name"
                        required
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <FileText size={16} />
                      Description
                    </label>
                    <textarea
                      name="description"
                      value={formData.description}
                      onChange={handleInputChange}
                      placeholder="Describe the application and scope of the threat modeling assessment"
                      rows={4}
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Lock size={16} />
                        Authentication Method
                      </label>
                      <input
                        type="text"
                        name="authentication_method"
                        value={formData.authentication_method}
                        onChange={handleInputChange}
                        placeholder="e.g., OAuth2, JWT, Basic Auth"
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Database size={16} />
                        Handles Sensitive Data
                      </label>
                      <select
                        name="handles_sensitive_data"
                        value={formData.handles_sensitive_data}
                        onChange={handleInputChange}
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="">Select option</option>
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Shield size={16} />
                        Data Classification
                      </label>
                      <input
                        type="text"
                        name="data_classification"
                        value={formData.data_classification}
                        onChange={handleInputChange}
                        placeholder="e.g., Public, Internal, Confidential, Restricted"
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Server size={16} />
                        Deployment Environment
                      </label>
                      <input
                        type="text"
                        name="deployment_environment"
                        value={formData.deployment_environment}
                        onChange={handleInputChange}
                        placeholder="e.g., AWS, Azure, On-premise"
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <FileText size={16} />
                        Compliance Requirements
                      </label>
                      <input
                        type="text"
                        name="compliance_requirements"
                        value={formData.compliance_requirements}
                        onChange={handleInputChange}
                        placeholder="e.g., GDPR, HIPAA, SOX, PCI-DSS"
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                        <Users size={16} />
                        User Types
                      </label>
                      <input
                        type="text"
                        name="user_types"
                        value={formData.user_types}
                        onChange={handleInputChange}
                        placeholder="e.g., Admin, Regular User, Guest"
                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Server size={16} />
                      Third Party Integrations
                    </label>
                    <input
                      type="text"
                      name="third_party_integrations"
                      value={formData.third_party_integrations}
                      onChange={handleInputChange}
                      placeholder="e.g., Payment gateways, Analytics services, APIs"
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Database size={16} />
                      Technology Stack
                    </label>
                    <textarea
                      name="technology_stack"
                      value={formData.technology_stack}
                      onChange={handleInputChange}
                      placeholder="Describe the technology stack (frontend, backend, database, etc.)"
                      rows={3}
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Server size={16} />
                      Deployment Environment Details
                    </label>
                    <input
                      type="text"
                      name="deployment_environment_detail"
                      value={formData.deployment_environment_detail}
                      onChange={handleInputChange}
                      placeholder="Additional deployment details"
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Shield size={16} />
                      Critical Assets
                    </label>
                    <input
                      type="text"
                      name="critical_assets"
                      value={formData.critical_assets}
                      onChange={handleInputChange}
                      placeholder="Identify critical assets to protect"
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="   text-sm font-medium text-blue-300 mb-2 flex items-center gap-2">
                      <Upload size={16} />
                      Supporting Files
                    </label>
                    <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center hover:border-blue-500 transition-colors">
                      <input
                        type="file"
                        accept=".pdf, .docx, .xls, .xlsx, .txt, .png, .jpg, .jpeg"
                        multiple
                        onChange={handleFileUpload}
                        className="hidden"
                        id="files-input"
                      />
                      <label
                        htmlFor="files-input"
                        className="cursor-pointer block"
                      >
                        <div className="flex items-center justify-center gap-2 text-gray-400 mb-2">
                          <Upload size={20} />
                          <span>Click to upload supporting files</span>
                        </div>
                        <div className="text-sm text-gray-500">
                          Supports .pdf, .docx, .xls, .xlsx, .txt, .png, .jpg, .jpeg
                        </div>
                      </label>
                      {formData.files.length > 0 && (
                        <div className="mt-4 space-y-2">
                          {formData.files.map((file, index) => (
                            <div key={index} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg border border-green-600">
                              <div className="flex items-center gap-2 text-green-400 text-sm">
                                <FileText size={16} />
                                <span>{file.name}</span>
                              </div>
                              <button
                                type="button"
                                onClick={() => removeFile(index)}
                                className="text-red-400 hover:text-red-300 text-sm"
                              >
                                Remove
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex justify-end pt-4">
                    <button
                      type="submit"
                      disabled={submitLoading}
                      className={`flex items-center gap-2 px-8 py-3 rounded-lg font-medium transition-colors ${submitLoading
                        ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                        : 'bg-blue-600 hover:bg-blue-700 text-white'
                        }`}
                    >
                      {submitLoading ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                          Creating Assessment...
                        </>
                      ) : (
                        <>
                          <Shield size={16} />
                          Create Assessment
                        </>
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatModel;