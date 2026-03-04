// API Service Layer
// Base URL for the Architecture Assessment API
import * as Cookie from "../../utils/cookie";

const BASE_URL = "https://api.aitoolsuite.xyz/api/v1/architecture-assessment";

/**
 * Get access token from cookies
 */
const getToken = () => {
  const token = Cookie.get("accessToken");

  if (!token) {
    throw new Error("Authentication token missing. Please login again.");
  }

  return token.trim();
};

/**
 * Build authorization headers
 * For FormData requests do NOT set Content-Type —
 * browser adds it with the multipart boundary
 */
const authHeaders = (isFormData = false) => {
  const headers = {
    Authorization: `Bearer ${getToken()}`,
  };

  if (!isFormData) {
    headers["Content-Type"] = "application/json";
  }

  return headers;
};

/**
 * Generic fetch wrapper
 */
const apiFetch = async (url, options = {}) => {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ detail: "Request failed" }));

    throw new Error(error.detail || `HTTP ${response.status}`);
  }

  if (response.status === 204) return null;

  return response.json();
};

// ── Assessments ───────────────────────────────────────────────────────────────
// POST   /assessments/
export const createAssessment = (formData) =>
  apiFetch(`${BASE_URL}/assessments/`, { method: 'POST', headers: authHeaders(true), body: formData });

// GET    /assessments/
export const listAssessments = () =>
  apiFetch(`${BASE_URL}/assessments/`, { headers: authHeaders() });

// GET    /assessments/{id}/
export const getAssessmentDetails = (id) =>
  apiFetch(`${BASE_URL}/assessments/${id}/`, { headers: authHeaders() });

// PATCH  /assessments/{id}/
export const updateAssessment = (id, formData) =>
  apiFetch(`${BASE_URL}/assessments/${id}/`, { method: 'PATCH', headers: authHeaders(true), body: formData });

// DELETE /assessments/{id}/
export const deleteAssessment = (id) =>
  apiFetch(`${BASE_URL}/assessments/${id}/`, { method: 'DELETE', headers: authHeaders() });

// GET    /assessments/{id}/report/
export const downloadExcelReport = async (id) => {
  const res = await fetch(`${BASE_URL}/assessments/${id}/report/`, { headers: authHeaders() });
  if (!res.ok) throw new Error('Download failed');
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `assessment_report_${id}.xlsx`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
};

// GET    /assessments/{id}/history/
export const getAssessmentHistory = (id) =>
  apiFetch(`${BASE_URL}/assessments/${id}/history/`, { headers: authHeaders() });

// ── Statistics ────────────────────────────────────────────────────────────────
// GET    /statistics/
export const getStatistics = () =>
  apiFetch(`${BASE_URL}/statistics/`, { headers: authHeaders() });

// ── Vulnerabilities ───────────────────────────────────────────────────────────
// Vulnerabilities live under an assessment but are addressed by their own ID
// for update/delete (not nested under assessment in the URL).

// GET    /assessments/{assessmentId}/vulnerabilities/
export const listVulnerabilities = (assessmentId) =>
  apiFetch(`${BASE_URL}/assessments/${assessmentId}/vulnerabilities/`, { headers: authHeaders() });

// PATCH  /vulnerabilities/{vulnId}/      ← flat URL, only vulnId needed
export const updateVulnerabilityStatus = (vulnId, data) =>
  apiFetch(`${BASE_URL}/vulnerabilities/${vulnId}/`, {
    method: 'PATCH', headers: authHeaders(), body: JSON.stringify(data),
  });

// ── Controls ──────────────────────────────────────────────────────────────────
// GET    /vulnerabilities/{vulnId}/controls/
export const listControlsForVulnerability = (vulnId) =>
  apiFetch(`${BASE_URL}/vulnerabilities/${vulnId}/controls/`, { headers: authHeaders() });

// POST   /vulnerabilities/{vulnId}/controls/
export const createControl = (vulnId, data) =>
  apiFetch(`${BASE_URL}/vulnerabilities/${vulnId}/controls/`, {
    method: 'POST', headers: authHeaders(), body: JSON.stringify(data),
  });

// PATCH  /controls/{controlId}/          ← flat URL, only controlId needed
export const updateControl = (controlId, data) =>
  apiFetch(`${BASE_URL}/controls/${controlId}/`, {
    method: 'PATCH', headers: authHeaders(), body: JSON.stringify(data),
  });

// GET    /controls/{controlId}/          ← same endpoint as get/update, returns history
export const getControlUpdateHistory = (controlId) =>
  apiFetch(`${BASE_URL}/controls/${controlId}/`, { headers: authHeaders() });

// DELETE /controls/{controlId}/          ← flat URL, only controlId needed
export const deleteControl = (controlId) =>
  apiFetch(`${BASE_URL}/controls/${controlId}/`, { method: 'DELETE', headers: authHeaders() });