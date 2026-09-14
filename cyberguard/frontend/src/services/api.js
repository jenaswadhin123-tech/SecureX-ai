import axios from 'axios';

const API_BASE = '/api';
const DEFAULT_API_KEY = 'cyberguard-secret-key-2026';

axios.defaults.headers.common['X-API-Key'] = DEFAULT_API_KEY;

export const fetchEvents = async (skip = 0, limit = 100, riskLevel = null) => {
  const params = { skip, limit };
  if (riskLevel && riskLevel !== 'ALL') {
    params.risk_level = riskLevel;
  }
  const response = await axios.get(`${API_BASE}/events`, { params });
  return response.data;
};

export const fetchTotalCount = async () => {
  const response = await axios.get(`${API_BASE}/events`, { params: { skip: 0, limit: 1 } });
  const total = response.headers['x-total-count'];
  if (total !== undefined) return parseInt(total, 10);
  return response.data.length;
};

export const analyzeUrl = async (url) => {
  const response = await axios.post(`${API_BASE}/analyze/url`, { url });
  return response.data;
};

export const analyzePhishing = async (content) => {
  const response = await axios.post(`${API_BASE}/analyze/phishing`, { content });
  return response.data;
};

export const analyzeAccount = async (log) => {
  const response = await axios.post(`${API_BASE}/analyze/account`, { log });
  return response.data;
};

export const analyzeVoice = async (audioFile) => {
  const formData = new FormData();
  formData.append('file', audioFile);
  const response = await axios.post(`${API_BASE}/analyze/voice`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};


export const explainThreat = async (threatEvent) => {
  const response = await axios.post(`${API_BASE}/explain`, threatEvent);
  return response.data;
};

export const checkHealth = async () => {
  try {
    const response = await axios.get(`${API_BASE}/health`, { timeout: 3000 });
    return response.status === 200;
  } catch (e) {
    return false;
  }
};

export const testWebhookAlert = async (webhookUrl) => {
  const response = await axios.post(`${API_BASE}/alerts/test`, { webhook_url: webhookUrl });
  return response.data;
};

export const exportEventsCSV = async (riskLevel = null) => {
  const params = {};
  if (riskLevel && riskLevel !== 'ALL') {
    params.risk_level = riskLevel;
  }
  const response = await axios.get(`${API_BASE}/events/export`, {
    params,
    responseType: 'blob',
  });
  // Trigger browser download
  const url = window.URL.createObjectURL(new Blob([response.data], { type: 'text/csv' }));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'cyberguard_events_report.csv');
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};
