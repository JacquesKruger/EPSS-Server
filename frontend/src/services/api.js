import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiService = {
  getDashboardData: async () => {
    const response = await api.get('/api/v1/dashboard');
    return response.data;
  },
  
  getVulnerabilities: async (params = {}) => {
    const response = await api.get('/api/v1/vulnerabilities', { params });
    return response.data;
  },
  
  uploadFile: async (file, scanType, scanName) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('scan_type', scanType);
    if (scanName) formData.append('scan_name', scanName);
    
    const response = await api.post('/api/v1/upload/csv', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  
  getReports: async (params = {}) => {
    const response = await api.get('/api/v1/reports', { params });
    return response.data;
  },

  generateReport: async (params = {}) => {
    const response = await api.post('/api/v1/reports/generate', null, { params });
    return response.data;
  },

  downloadScanCsv: async (scanId) => {
    const url = `/api/v1/reports/export/scan/${scanId}`;
    // Return full URL so caller can set window.location = url for browser download
    return `${API_BASE_URL}${url}`;
  },
  
  getRiskAnalysis: async (params = {}) => {
    const response = await api.get('/api/v1/risk-analysis', { params });
    return response.data;
  },
};

export default api;
