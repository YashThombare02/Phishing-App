import axios from 'axios';

// Define the base URL for API requests
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';
console.log('API base URL is configured as:', API_BASE_URL);

// Add a timeout to prevent hanging requests
axios.defaults.timeout = 20000; // 20 seconds timeout
// Add CORS headers
axios.defaults.headers.common['Access-Control-Allow-Origin'] = '*';

// Define types for API responses
export interface VerificationMethod {
  result: boolean;
  description: string;
  value?: number;
}

export interface DetectionResult {
  url: string;
  verification_methods: {
    phishtank: VerificationMethod;
    google_safe_browsing: VerificationMethod;
    uci_model: VerificationMethod;
    advanced_model: VerificationMethod;
    domain_age_days: VerificationMethod;
    domain_created: string;
  };
  final_verdict: boolean;
  confidence: number;
  explanations: string[];
  features_extracted: {
    uci_features: number;
    advanced_features: number;
  };
  error?: string;
}

export interface BatchDetectionResult {
  results: DetectionResult[];
}

export interface ApiStats {
  models_loaded: boolean;
  phishtank_checks: number;
  safebrowsing_checks: number;
  whois_checks: number;
  status: string;
  api_version: string;
}

export interface VerificationMethodInfo {
  name: string;
  description: string;
  accuracy: string;
  type: string;
}

export interface VerificationMethodsResponse {
  verification_methods: VerificationMethodInfo[];
}

export interface StatisticsResponse {
  total_urls_analyzed: number;
  phishing_percentage: number;
  legitimate_percentage: number;
  total_phishing: number;
  total_legitimate: number;
  common_tlds: Record<string, number>;
  recent_detections: {
    url: string;
    is_phishing: boolean;
    timestamp: string;
  }[];
}

export interface SearchHistoryResponse {
  records: {
    id: number;
    url: string;
    is_phishing: boolean;
    timestamp: string;
    score?: number;
  }[];
  total: number;
  page: number;
  total_pages: number;
}

export interface AnalysisResult {
  url: string;
  isPhishing: boolean;
  score: number;
  reasons: string[];
  features: {
    domain: string;
    subdomain: string;
    domainName: string;
    tld: string;
    usesHttps: boolean;
    containsHyphens: boolean;
    containsNumbers: boolean;
    suspiciousTld: boolean;
    pathIndicators: string[];
  };
  detailedAnalysis: {
    brandImpersonation?: string;
    suspiciousElements: string[];
    technicalDetails: string[];
  };
}

export interface ReportResponse {
  success: boolean;
  message: string;
}

export interface Report {
  id: number;
  url: string;
  domain: string;
  description: string;
  username: string;
  timestamp: string;
  status: string;
}

export interface ReportsResponse {
  reports: Report[];
  page: number;
  total_pages: number;
  total_records: number;
}

// API Health Check
export const checkApiHealth = async (): Promise<boolean> => {
  try {
    console.log('Checking API health...');
    const response = await axios.get(`${API_BASE_URL}/health`, { timeout: 5000 });
    console.log('API health check response:', response.status, response.data);
    return response.status === 200 && response.data.status === 'ok';
  } catch (error) {
    console.error('API health check failed:', error);
    return false;
  }
};

// API functions
export const detectUrl = async (url: string): Promise<DetectionResult> => {
  try {
    console.log('Starting API call to detectUrl with:', url);
    // Make request with longer timeout for slow connections
    const config = {
      timeout: 30000 // 30 seconds timeout
    };
    
    // In a real implementation, this would call your backend API
    const response = await axios.post(`${API_BASE_URL}/detect`, { url }, config);
    console.log('API response received:', response.status, response.statusText);
    
    if (!response.data) {
      throw new Error('Received empty response from server');
    }
    
    return response.data;
  } catch (error: any) {
    console.error('Error detecting URL:', error);
    
    // Enhanced error handling with specific messages
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('Server response error:', error.response.status, error.response.data);
      throw new Error(`Server error: ${error.response.status} - ${error.response.data?.error || 'Unknown error'}`);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No response received:', error.request);
      throw new Error('No response from server. Please check if the backend is running.');
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Request setup error:', error.message);
      throw new Error(`Request failed: ${error.message}`);
    }
  }
};

export const batchDetectUrls = async (urls: string[]): Promise<BatchDetectionResult> => {
  try {
    const response = await axios.post(`${API_BASE_URL}/batch_detect`, { urls });
    return response.data;
  } catch (error) {
    console.error('Error batch detecting URLs:', error);
    throw error;
  }
};

export const getApiStats = async (): Promise<ApiStats> => {
  try {
    const response = await axios.get(`${API_BASE_URL}/stats`);
    return response.data;
  } catch (error) {
    console.error('Error getting API stats:', error);
    throw error;
  }
};

export const getStatistics = async (): Promise<StatisticsResponse> => {
  try {
    // First try the original endpoint
    console.log('Trying to fetch statistics from primary endpoint...');
    try {
      const response = await axios.get(`${API_BASE_URL}/statistics`);
      console.log('Statistics fetch successful');
      return response.data;
    } catch (error) {
      console.error('Error with primary statistics endpoint, trying fallback:', error);
      
      // If that fails, try the v2 endpoint
      const fallbackResponse = await axios.get(`${API_BASE_URL}/statistics_v2`);
      console.log('Fallback statistics fetch successful');
      return fallbackResponse.data;
    }
  } catch (error) {
    console.error('Error getting statistics from both endpoints:', error);
    throw error;
  }
};

export const reportPhishingSite = async (url: string, username: string = 'Anonymous', description: string = ''): Promise<ReportResponse> => {
  try {
    const response = await axios.post(`${API_BASE_URL}/report`, { url, username, description });
    return response.data;
  } catch (error) {
    console.error('Error reporting phishing site:', error);
    throw error;
  }
};

export const getReports = async (page: number = 1, limit: number = 10): Promise<ReportsResponse> => {
  try {
    console.log('Fetching reports:', { page, limit });
    const response = await axios.get(`${API_BASE_URL}/reports`, {
      params: { page, limit }
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching reports:', error);
    throw error;
  }
};

export const getVerificationMethods = async (): Promise<VerificationMethodsResponse> => {
  try {
    const response = await axios.get(`${API_BASE_URL}/verification_methods`);
    return response.data;
  } catch (error) {
    console.error('Error getting verification methods:', error);
    throw error;
  }
};

export const analyzeUrl = async (url: string): Promise<AnalysisResult> => {
  try {
    console.log('analyzeUrl called with:', url);
    
    // In a real implementation, this would call your backend API
    // For now, we'll use the regular detection endpoint and transform the response
    const response = await detectUrl(url);
    console.log('detectUrl response received:', response);
    
    // Parse domain info
    let domain = '';
    let subdomain = '';
    let domainName = '';
    let tld = '';
    
    try {
      const urlObj = new URL(url);
      domain = urlObj.hostname;
      
      // Extract domain parts
      const domainParts = domain.split('.');
      if (domainParts.length >= 2) {
        tld = domainParts.pop() || '';
        domainName = domainParts.pop() || '';
        subdomain = domainParts.join('.');
      }
    } catch (err) {
      console.error('Error parsing URL:', err);
    }
    
    // Ensure we have verification_methods
    const verification_methods = response.verification_methods || {};
    
    // Ensure features_extracted exists
    const features_extracted = response.features_extracted || { uci_features: 0, advanced_features: 0 };
    
    // Transform the response into the AnalysisResult format
    return {
      url,
      isPhishing: response.final_verdict,
      score: parseFloat((response.confidence / 100).toFixed(2)), // Convert from percentage to decimal with 2 decimal places
      reasons: response.explanations || [],
      features: {
        domain,
        subdomain,
        domainName,
        tld,
        usesHttps: url.startsWith('https'),
        containsHyphens: domain.includes('-'),
        containsNumbers: /\d/.test(domain),
        suspiciousTld: ['xyz', 'tk', 'ml', 'ga', 'cf', 'page'].includes(tld),
        pathIndicators: []
      },
      detailedAnalysis: {
        brandImpersonation: response.explanations?.find(exp => exp.toLowerCase().includes('brand') || exp.toLowerCase().includes('impersonat')) || undefined,
        suspiciousElements: Object.entries(verification_methods)
          .filter(([_, method]) => (method as VerificationMethod).result)
          .map(([name, method]) => (method as VerificationMethod).description),
        technicalDetails: [
          `URL was analyzed using ${Object.keys(verification_methods).length} different verification methods`,
          `Machine learning models detected ${features_extracted.uci_features} suspicious features`,
          `Advanced analysis revealed ${features_extracted.advanced_features} potential risk indicators`,
          ...Object.entries(verification_methods).map(([name, method]) => 
            `${name.replace('_', ' ')}: ${(method as VerificationMethod).description}`)
        ]
      }
    };
  } catch (error: any) {
    console.error('Error analyzing URL:', error);
    // Provide a more helpful error message
    if (error.message?.includes('No response from server')) {
      throw new Error('Backend server appears to be offline. Please check if it\'s running.');
    } else {
      throw error;
    }
  }
};

export const getSearchHistory = async (
  page: number = 1, 
  limit: number = 10, 
  filter: string = 'all'
): Promise<SearchHistoryResponse> => {
  try {
    console.log('Fetching search history with params:', { page, limit, filter });
    
    // Call the actual backend API
    const response = await axios.get(`${API_BASE_URL}/search_history`, {
      params: { page, limit, filter }
    });
    
    console.log('Search history response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching search history:', error);
    throw error;
  }
};
