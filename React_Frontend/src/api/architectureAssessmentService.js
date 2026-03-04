import axios from 'axios';
import { getAuthCookies } from "./auth";

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;
const API_URL = `${API_BASE_URL}/api/v1/architecture-assessment`;

/**
 * Create a new architecture assessment
 * @param {FormData} formData - Form data containing all assessment fields and architecture_diagram file
 * @returns {Promise} API response with created assessment
 */
export const createAssessment = async (formData) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.post(`${API_URL}/assessments/`, formData, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "multipart/form-data"
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error creating assessment:', error);
    throw error;
  }
};

/**
 * Fetch all assessments with optional filters
 * @param {Object} filters - Optional filters (status, min_score, max_score)
 * @returns {Promise} Array of assessments
 */
export const fetchAssessments = async (filters = {}) => {
  try {
    const token = getAuthCookies().accessToken;
    const queryParams = new URLSearchParams();

    if (filters.status) queryParams.append('status', filters.status);
    if (filters.min_score) queryParams.append('min_score', filters.min_score);
    if (filters.max_score) queryParams.append('max_score', filters.max_score);

    const url = `${API_URL}/list-assessment/${queryParams.toString() ? '?' + queryParams.toString() : ''}`;

    const response = await axios.get(url, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching assessments:', error);
    throw error;
  }
};

/**
 * Fetch history for a specific assessment
 * @param {string} id - Assessment ID
 * @returns {Promise} Array of history items
 */
export const fetchAssessmentHistory = async (id) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.get(`${API_URL}/assessment-history/?assessment=${id}`, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error fetching history for assessment ${id}:`, error);
    throw error;
  }
};

/**
 * Fetch detailed information for a specific assessment
 * @param {string} id - Assessment ID
 * @returns {Promise} Assessment details including vulnerable_components
 */
export const fetchAssessmentDetails = async (id) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.get(`${API_URL}/assessments/${id}/`, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error fetching assessment ${id}:`, error);
    throw error;
  }
};

/**
 * Update specific fields of an assessment
 * Only application_purpose, business_objectives, stakeholders, system_owners, compliance_requirements can be updated
 * @param {string} id - Assessment ID
 * @param {Object} data - Fields to update
 * @returns {Promise} Updated assessment data
 */
export const updateAssessment = async (id, data) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.patch(`${API_URL}/assessments/${id}/`, data, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error updating assessment ${id}:`, error);
    throw error;
  }
};

/**
 * Delete an assessment
 * @param {string} id - Assessment ID
 * @returns {Promise} Success indicator
 */
export const deleteAssessment = async (id) => {
  try {
    const token = getAuthCookies().accessToken;
    await axios.delete(`${API_URL}/assessments/${id}/`, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return true;
  } catch (error) {
    console.error(`Error deleting assessment ${id}:`, error);
    throw error;
  }
};

/**
 * Get architecture assessment statistics
 * @returns {Promise} Statistics object
 */
export const getStatistics = async () => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.get(`${API_URL}/statistics/`, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching statistics:', error);
    throw error;
  }
};

/**
 * Download assessment report
 * @param {string} id - Assessment ID
 * @returns {Promise} Blob containing the report
 */
export const downloadReport = async (id) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.get(`${API_URL}/assessments/${id}/report/`, {
      headers: {
        "Authorization": `Bearer ${token}`
      },
      responseType: 'blob'
    });
    return response.data;
  } catch (error) {
    console.error(`Error downloading report for ${id}:`, error);
    throw error;
  }
};

/**
 * Update vulnerability status or details
 * @param {string} id - Vulnerability ID
 * @param {Object} data - fields to update
 * @returns {Promise} Updated vulnerability data
 */
export const updateVulnerability = async (id, data) => {
  try {
    const token = getAuthCookies().accessToken;
    const response = await axios.patch(`${API_URL}/vulnerabilities/${id}/`, data, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error updating vulnerability ${id}:`, error);
    throw error;
  }
};

/**
 * Add a remediation control to a vulnerability
 * @param {string} vulnId - Vulnerability ID
 * @param {Object} controlData - Control data
 * @returns {Promise} Created control
 */
export const addControl = async (vulnId, controlData) => {
  try {
    const token = getAuthCookies().accessToken;
    // Handle file uploads if evidence files are included
    const isFormData = controlData instanceof FormData;
    const headers = {
      "Authorization": `Bearer ${token}`
    };

    if (isFormData) {
      headers["Content-Type"] = "multipart/form-data";
    } else {
      headers["Content-Type"] = "application/json";
    }

    const response = await axios.post(`${API_URL}/vulnerabilities/${vulnId}/controls/`, controlData, {
      headers
    });
    return response.data;
  } catch (error) {
    console.error(`Error adding control to vuln ${vulnId}:`, error);
    throw error;
  }
};

/**
 * Update a remediation control
 * @param {string} controlId - Control ID
 * @param {Object} controlData - Data to update
 * @returns {Promise} Updated control
 */
export const updateControl = async (controlId, controlData) => {
  try {
    const token = getAuthCookies().accessToken;
    // Handle file uploads if evidence files are included
    const isFormData = controlData instanceof FormData;
    const headers = {
      "Authorization": `Bearer ${token}`
    };

    if (isFormData) {
      headers["Content-Type"] = "multipart/form-data";
    } else {
      headers["Content-Type"] = "application/json";
    }

    const response = await axios.patch(`${API_URL}/controls/${controlId}/`, controlData, {
      headers
    });
    return response.data;
  } catch (error) {
    console.error(`Error updating control ${controlId}:`, error);
    throw error;
  }
};

/**
 * Delete a remediation control
 * @param {string} controlId - Control ID
 * @returns {Promise} Success indicator
 */
export const deleteControl = async (controlId) => {
  try {
    const token = getAuthCookies().accessToken;
    await axios.delete(`${API_URL}/controls/${controlId}/`, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return true;
  } catch (error) {
    console.error(`Error deleting control ${controlId}:`, error);
    throw error;
  }
};
