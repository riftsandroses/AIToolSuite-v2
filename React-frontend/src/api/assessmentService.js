import axios from 'axios';
import { getAuthCookies } from "./auth";



const token = getAuthCookies().accessToken;

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;
const API_URL = `${API_BASE_URL}/api/v1/risk-assessment`;

export const fetchAssessments = async () => {
  try {
    const response = await axios.get(`${API_URL}/assessments/`,
      {
        headers: {
        "Authorization": `Bearer ${token}`
      }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error fetching assessments:', error);
    throw error;
  }
};

export const createAssessment = async (assessmentData) => {
  try {
    const response = await axios.post(`${API_URL}/assessments/`, assessmentData,{
      headers: {
        "Authorization": `Bearer ${token}`
      }
    }
    );
    return response.data;
  } catch (error) {
    console.error('Error creating assessment:', error);
    throw error;
  }
};

export const updateAssessment = async (id, assessmentData) => {
  try {
    const response = await axios.put(`${API_URL}/assessments/${id}/`, assessmentData,{
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error updating assessment ${id}:`, error);
    throw error;
  }
};

export const deleteAssessment = async (id) => {
  try {
    await axios.delete(`${API_URL}/assessments/${id}/`,{
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