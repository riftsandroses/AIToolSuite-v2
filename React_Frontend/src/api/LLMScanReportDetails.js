import { getAuthCookies } from './auth';

const API_BASE_URL = import.meta.env.VITE_API_URL
const BASE_URL = `${API_BASE_URL}/api/v1/scanner-results/results`;

const getHeaders = () => {
  const { accessToken } = getAuthCookies();
  return {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
  };
};

export const getScannerResults = async (id, scanType) => {
  try {
    const endpoint = scanType === 'azure' 
      ? `${BASE_URL}/by_azure_scan/?id=${id}`
      : `${BASE_URL}/by_openai_scan/?id=${id}`;
    
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching scanner results:', error);
    throw error;
  }
};

export const downloadScannerResults = async (id, scanType) => {
  try {
    const response = await fetch(
      `${BASE_URL}/download_unencrypted_zip/?id=${id}&type=${scanType}`,
      {
        method: 'GET',
        headers: getHeaders(),
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Create blob and download
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `scanner-results-${id}-${scanType}.zip`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (error) {
    console.error('Error downloading scanner results:', error);
    throw error;
  }
};

export const getCategoryDistribution = async (id, scanType) => {
  try {
    const endpoint = scanType === 'azure' 
      ? `${BASE_URL}/category_distribution_azure/?id=${id}`
      : `${BASE_URL}/category_distribution_openai/?id=${id}`;
    
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching category distribution:', error);
    throw error;
  }
};

export const getSeverityCounts = async (id, scanType) => {
  try {
    const endpoint = scanType === 'azure' 
      ? `${BASE_URL}/severity_counts_azure/?id=${id}`
      : `${BASE_URL}/severity_counts_openai/?id=${id}`;
    
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching severity counts:', error);
    throw error;
  }
};