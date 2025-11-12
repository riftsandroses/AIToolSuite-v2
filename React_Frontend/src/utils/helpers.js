import { getAuthCookies } from "../api/auth";

export const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
};

export const callBackend =  async (route, method = 'GET', data = null) => {
  try {
    const token = getAuthCookies().accessToken;
    
    const baseURL = process.env.REACT_APP_API_BASE_URL

    const url = `${baseURL}${route}`;
    
    const config = {
      method: method.toUpperCase(),
      headers: {
        'Content-Type': 'application/json',
      }
    };
    
    config.headers['Authorization'] = `Bearer ${token}`;
    
    if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      config.body = JSON.stringify(data);
    }
    
    const response = await fetch(url, config);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return response;
    
  } catch (error) {
    console.error('API Request Error:', error);
    throw error;
  }
}