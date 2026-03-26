import { getAuthCookies } from "./auth";



const token = getAuthCookies().accessToken;

// Base URL for API
const API_BASE_URL = import.meta.env.VITE_API_URL;
const BASE_URL = `${API_BASE_URL}/api/v1/scanner-results/results`;
/**
 * Fetches all OpenAI scans from the API
 * @returns {Promise} Promise that resolves to scan data
 */
export const fetchOpenAIScans = async () => {
  try {
    const response = await fetch(`${BASE_URL}/all_openai_scans/`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error("Failed to fetch OpenAI scans");
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching OpenAI scans:", error);
    throw error;
  }
};

/**
 * Fetches all Azure scans from the API
 * @returns {Promise} Promise that resolves to scan data
 */
export const fetchAzureScans = async () => {
  try {
    const response = await fetch(`${BASE_URL}/all_azure_scans/`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error("Failed to fetch Azure scans");
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching Azure scans:", error);
    throw error;
  }
};

/**
 * Fetches all scans from multiple providers and combines the results
 * @returns {Promise} Promise that resolves to combined scan data
 */
export const fetchAllScans = async () => {
  try {
    const [openAIData, azureData] = await Promise.all([
      fetchOpenAIScans(),
      fetchAzureScans()
    ]);
    
    // Combine the scans from both sources
    const combinedScans = [
      ...(openAIData.scans || []),
      ...(azureData.scans || [])
    ];
    
    return combinedScans;
  } catch (error) {
    console.error("Error fetching combined scans:", error);
    throw error;
  }
};