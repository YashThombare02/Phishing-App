import React, { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import PhishingAnalysisReport from '@/components/PhishingAnalysisReport';
import { FaSearch, FaSpinner, FaShieldAlt, FaLock, FaUnlock, FaFingerprint, FaNetworkWired, FaBug, FaSearchLocation } from 'react-icons/fa';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { analyzeUrl as apiAnalyzeUrl, checkApiHealth } from '@/utils/api';
import { formatUrl, isValidUrl } from '@/utils/urlUtils';

// This would normally come from your API
const analyzeUrl = async (url: string) => {
  // For a real implementation, use the API function
  return await apiAnalyzeUrl(url);
};

const HomePage: React.FC = () => {
  const router = useRouter();
  const { url: urlParam } = router.query;
  
  const [url, setUrl] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [apiAvailable, setApiAvailable] = useState<boolean | null>(null);

  // Check API health on component mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const isHealthy = await checkApiHealth();
        setApiAvailable(isHealthy);
        if (!isHealthy) {
          console.warn('API health check failed - backend may not be available');
        }
      } catch (err) {
        console.error('Error checking API health:', err);
        setApiAvailable(false);
      }
    };
    
    checkHealth();
  }, []);

  useEffect(() => {
    if (urlParam && typeof urlParam === 'string') {
      setUrl(urlParam);
      handleAnalyze(urlParam);
    }
  }, [urlParam]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }
    
    handleAnalyze(url);
  };

  const handleAnalyze = async (urlToAnalyze: string) => {
    try {
      console.log('Starting analysis for URL:', urlToAnalyze);
      
      // Check API health before proceeding
      if (apiAvailable === false) {
        // Try one more time
        const isHealthy = await checkApiHealth();
        if (!isHealthy) {
          setError('Unable to connect to the analysis server. Please ensure the backend is running at http://localhost:5000.');
          return;
        } else {
          setApiAvailable(true);
        }
      }
      
      setLoading(true);
      setError(null);
      setAnalysisResult(null); // Clear any previous results
      
      // Clean and format URL
      let formattedUrl = urlToAnalyze.trim();
      
      // Remove any whitespace, tabs, or duplicate protocols
      formattedUrl = formattedUrl.replace(/\s+/g, '');
      
      // Check if we have duplicate http/https prefixes
      const protocolMatch = formattedUrl.match(/^(https?:\/\/)+/i);
      if (protocolMatch && protocolMatch[0] !== 'http://' && protocolMatch[0] !== 'https://') {
        // If we have duplicate protocols, take only the last one
        formattedUrl = formattedUrl.replace(/^(https?:\/\/)+/i, '');
        formattedUrl = `https://${formattedUrl}`;
      } else if (!formattedUrl.startsWith('http')) {
        formattedUrl = `https://${formattedUrl}`;
      }
      
      console.log('Formatted URL:', formattedUrl);
      
      // Validate URL
      if (!isValidUrl(formattedUrl)) {
        setError('Please enter a valid URL');
        setLoading(false);
        return;
      }
      
      console.log('Calling API with URL:', formattedUrl);
      
      // Simple ping test before calling the main API
      try {
        await fetch(`${window.location.protocol}//${window.location.hostname}:5000/api/stats`, {
          method: 'HEAD',
          mode: 'no-cors'
        });
      } catch (pingErr) {
        console.error('Backend ping test failed:', pingErr);
        // Continue anyway - just a test
      }
      
      const result = await analyzeUrl(formattedUrl);
      console.log('API call successful, result:', result);
      
      if (!result) {
        throw new Error('Received empty result from API');
      }
      
      setAnalysisResult(result);
      
      // Update URL in browser if it was changed
      if (formattedUrl !== urlToAnalyze) {
        router.replace(`/?url=${encodeURIComponent(formattedUrl)}`, undefined, { shallow: true });
      }
    } catch (err: any) {
      console.error('Error during analysis:', err);
      
      // Improved error handling with more specific messages
      if (err.message?.includes('No response from server') || 
          err.message?.includes('Backend server appears to be offline') || 
          err.message?.includes('Network Error')) {
        setError('Unable to connect to the analysis server. Please ensure the backend is running and accessible at http://localhost:5000.');
      } else if (err.response?.status === 500) {
        setError('The server encountered an error while analyzing the URL. Please try again later.');
      } else if (err.response?.data?.error) {
        setError(`Error: ${err.response.data.error}`);
      } else {
        setError(err.message || 'An error occurred during URL analysis');
      }
      setAnalysisResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout activePage="home">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center mb-12 relative">
          {/* Cyber glow effect */}
          <div className="absolute inset-0 bg-glow-effect opacity-50 blur-xl"></div>
          
          <div className="flex justify-center mb-6">
            <div className="relative">
              <FaShieldAlt className="h-20 w-20 text-cyber-accent animate-pulse-glow" />
              <div className="absolute inset-0 animate-cyber-scan rounded-full"></div>
            </div>
          </div>
          
          <h1 className="text-4xl font-extrabold text-white sm:text-5xl sm:tracking-tight lg:text-6xl font-cyber">
            <span className="text-cyber-accent">PhishGuard</span> URL Analyzer
          </h1>
          <p className="mt-4 max-w-2xl mx-auto text-xl text-gray-300">
            Enter a URL to analyze it for phishing indicators and get a detailed security report.
          </p>
          
          <div className="flex justify-center mt-8 space-x-12">
            <div className="text-center">
              <div className="rounded-full bg-cyber-dark p-3 inline-block border border-cyber-accent/30 shadow-cyber-glow mb-2">
                <FaLock className="h-6 w-6 text-cyber-accent" />
              </div>
              <p className="text-gray-400">Advanced<br/>Security</p>
            </div>
            <div className="text-center">
              <div className="rounded-full bg-cyber-dark p-3 inline-block border border-cyber-accent/30 shadow-cyber-glow mb-2">
                <FaFingerprint className="h-6 w-6 text-cyber-accent" />
              </div>
              <p className="text-gray-400">Identity<br/>Protection</p>
            </div>
            <div className="text-center">
              <div className="rounded-full bg-cyber-dark p-3 inline-block border border-cyber-accent/30 shadow-cyber-glow mb-2">
                <FaNetworkWired className="h-6 w-6 text-cyber-accent" />
              </div>
              <p className="text-gray-400">Domain<br/>Analysis</p>
            </div>
          </div>
          
          {apiAvailable === false && (
            <div className="mt-4 max-w-3xl mx-auto bg-cyber-dark border border-cyber-warning/50 rounded-md p-4">
              <div className="flex items-center">
                <svg className="h-5 w-5 text-cyber-warning" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <p className="ml-3 text-sm text-cyber-warning">
                  Backend API not available. Please ensure the server is running at http://localhost:5000.
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="max-w-3xl mx-auto mb-10 relative">
          <div className="absolute -inset-1 bg-cyber-gradient rounded-lg blur opacity-25"></div>
          <form onSubmit={handleSubmit} className="relative flex shadow-cyber-glow rounded-lg overflow-hidden">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to analyze (e.g., https://example.com)"
              className="flex-grow px-4 py-3 bg-cyber-dark border-cyber-accent/30 border text-white rounded-l-md focus:ring-cyber-accent focus:border-cyber-accent"
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-cyber-gradient text-white px-6 py-3 rounded-r-md hover:bg-opacity-90 focus:outline-none focus:ring-2 focus:ring-cyber-accent focus:ring-offset-2 focus:ring-offset-cyber-dark disabled:opacity-50 shadow-cyber-glow"
            >
              {loading ? (
                <FaSpinner className="animate-spin h-5 w-5" />
              ) : (
                <FaSearch className="h-5 w-5" />
              )}
            </button>
          </form>
          
          {error && (
            <div className="mt-4 p-4 bg-cyber-dark border border-danger-500 text-danger-400 rounded-md shadow-cyber-glow">
              {error}
            </div>
          )}
        </div>

        {loading && !analysisResult && (
          <div className="max-w-3xl mx-auto text-center py-10">
            <div className="relative">
              <div className="absolute inset-0 bg-glow-effect opacity-75"></div>
              <FaSpinner className="animate-spin h-10 w-10 mx-auto text-cyber-accent mb-4 relative" />
            </div>
            <p className="text-gray-300">Analyzing URL for potential phishing indicators...</p>
            <p className="text-gray-400 text-sm mt-2">This may take a few moments.</p>
          </div>
        )}

        {!loading && analysisResult && (
          <div className="max-w-4xl mx-auto">
            <PhishingAnalysisReport
              url={analysisResult.url}
              isPhishing={analysisResult.isPhishing}
              score={analysisResult.score}
              reasons={analysisResult.reasons}
              features={analysisResult.features}
              detailedAnalysis={analysisResult.detailedAnalysis}
            />
            
            <div className="mt-8 text-center">
              <p className="text-gray-300 mb-4">
                Think this analysis is incorrect? Help improve our system by reporting it.
              </p>
              <Link href="/report" passHref>
                <button className="inline-flex justify-center py-2 px-6 border border-transparent shadow-cyber-glow text-sm font-medium rounded-md text-white bg-cyber-gradient hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-cyber-accent focus:ring-offset-2 focus:ring-offset-cyber-dark">
                  Report This URL
                </button>
              </Link>
            </div>
          </div>
        )}
        
        {!loading && !analysisResult && (
          <div className="mt-16">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
              <div className="bg-cyber-dark p-6 rounded-lg border border-cyber-accent/30 shadow-cyber-glow">
                <div className="flex items-center mb-4">
                  <div className="bg-cyber-dark rounded-full p-2 border border-cyber-accent/50">
                    <FaBug className="h-6 w-6 text-cyber-accent" />
                  </div>
                  <h3 className="ml-3 text-xl font-semibold text-white font-cyber">Phishing Detection</h3>
                </div>
                <p className="text-gray-300">Our system uses advanced machine learning algorithms to identify phishing attempts with high accuracy.</p>
              </div>
              
              <div className="bg-cyber-dark p-6 rounded-lg border border-cyber-accent/30 shadow-cyber-glow">
                <div className="flex items-center mb-4">
                  <div className="bg-cyber-dark rounded-full p-2 border border-cyber-accent/50">
                    <FaLock className="h-6 w-6 text-cyber-accent" />
                  </div>
                  <h3 className="ml-3 text-xl font-semibold text-white font-cyber">Security Analysis</h3>
                </div>
                <p className="text-gray-300">Get detailed reports on potential security threats including domain impersonation and suspicious elements.</p>
              </div>
              
              <div className="bg-cyber-dark p-6 rounded-lg border border-cyber-accent/30 shadow-cyber-glow">
                <div className="flex items-center mb-4">
                  <div className="bg-cyber-dark rounded-full p-2 border border-cyber-accent/50">
                    <FaSearchLocation className="h-6 w-6 text-cyber-accent" />
                  </div>
                  <h3 className="ml-3 text-xl font-semibold text-white font-cyber">Domain Intelligence</h3>
                </div>
                <p className="text-gray-300">We analyze domain characteristics, reputation history, and technical indicators to detect malicious websites.</p>
              </div>
            </div>
            
            <div className="text-center text-gray-400">
              <p className="max-w-3xl mx-auto">
                PhishGuard helps protect you from online threats by analyzing URLs for signs of phishing, malware, and other security risks. 
                Stay safe online with our advanced security analysis.
              </p>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default HomePage;
