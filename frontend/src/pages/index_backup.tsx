import React, { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import PhishingAnalysisReport from '@/components/PhishingAnalysisReport';
import { FaSearch, FaSpinner } from 'react-icons/fa';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { analyzeUrl as apiAnalyzeUrl } from '@/utils/api';
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
      setLoading(true);
      setError(null);
      
      // Format URL if needed
      let formattedUrl = urlToAnalyze;
      if (!formattedUrl.startsWith('http')) {
        formattedUrl = `https://${formattedUrl}`;
      }
      
      // Validate URL
      if (!isValidUrl(formattedUrl)) {
        setError('Please enter a valid URL');
        setLoading(false);
        return;
      }
      
      const result = await analyzeUrl(formattedUrl);
      setAnalysisResult(result);
      
      // Update URL in browser if it was changed
      if (formattedUrl !== urlToAnalyze) {
        router.replace(`/?url=${encodeURIComponent(formattedUrl)}`, undefined, { shallow: true });
      }
    } catch (err: any) {
      // Improved error handling with more specific messages
      if (err.message?.includes('No response from server') || err.message?.includes('Backend server appears to be offline')) {
        setError('Unable to connect to the analysis server. Please ensure the backend is running.');
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
        <div className="text-center mb-8">
          <h1 className="text-4xl font-extrabold text-gray-900 sm:text-5xl sm:tracking-tight lg:text-6xl">
            PhishGuard URL Analyzer
          </h1>
          <p className="mt-4 max-w-2xl mx-auto text-xl text-gray-500">
            Enter a URL to analyze it for phishing indicators and get a detailed security report.
          </p>
        </div>

        <div className="max-w-3xl mx-auto mb-10">
          <form onSubmit={handleSubmit} className="flex shadow-sm">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to analyze (e.g., https://example.com)"
              className="flex-grow px-4 py-3 rounded-l-md border border-gray-300 focus:ring-blue-500 focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-blue-600 text-white px-6 py-3 rounded-r-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
            >
              {loading ? (
                <FaSpinner className="animate-spin h-5 w-5" />
              ) : (
                <FaSearch className="h-5 w-5" />
              )}
            </button>
          </form>
          
          {error && (
            <div className="mt-4 p-4 bg-red-100 text-red-700 rounded-md">
              {error}
            </div>
          )}
        </div>

        {loading && !analysisResult && (
          <div className="max-w-3xl mx-auto text-center py-10">
            <FaSpinner className="animate-spin h-10 w-10 mx-auto text-blue-500 mb-4" />
            <p className="text-gray-600">Analyzing URL for potential phishing indicators...</p>
            <p className="text-gray-500 text-sm mt-2">This may take a few moments.</p>
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
              <p className="text-gray-600 mb-4">
                Think this analysis is incorrect? Help improve our system by reporting it.
              </p>
              <Link href="/report" passHref>
                <button className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                  Report This URL
                </button>
              </Link>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default HomePage;
  };
    
    try {
      // Call API
      const formattedUrl = formatUrl(url);
      const data = await detectUrl(formattedUrl);
      setResult(data);
    } catch (err: any) {
      // Improved error handling with more specific error messages
      if (err.message?.includes('No response from server')) {
        setError('Unable to connect to the analysis server. Please ensure the backend is running.');
      } else if (err.response?.status === 500) {
        setError('The server encountered an error while analyzing the URL. Please try again later.');
      } else if (err.response?.data?.error) {
        setError(`Error: ${err.response.data.error}`);
      } else {
        setError(err.message || 'An error occurred while analyzing the URL');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout activePage="home">
      <div className="bg-gradient-to-b from-primary-50 to-white">
        <div className="max-w-7xl mx-auto px-4 py-16 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl font-extrabold text-gray-900 sm:text-5xl sm:tracking-tight lg:text-6xl">
              Phishing URL Detection
            </h1>
            <p className="mt-4 max-w-2xl mx-auto text-xl text-gray-500">
              Analyze any URL using our advanced phishing detection engine powered by machine learning
              and real-time verification APIs.
            </p>
          </div>

          <div className="mt-12 max-w-3xl mx-auto">
            <form onSubmit={handleSubmit} className="mt-5 sm:flex">
              <div className="flex-1">
                <label htmlFor="url" className="sr-only">URL to check</label>
                <input
                  id="url"
                  name="url"
                  type="text"
                  required
                  className="input"
                  placeholder="Enter a URL to check (e.g., example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <div className="mt-3 sm:mt-0 sm:ml-3">
                <button
                  type="submit"
                  className="btn btn-primary w-full flex items-center justify-center"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="flex items-center">
                      <span className="animate-spin h-4 w-4 mr-2 border-2 border-white border-t-transparent rounded-full"></span>
                      Analyzing...
                    </span>
                  ) : (
                    <span className="flex items-center">
                      <FaSearch className="mr-2" />
                      Analyze URL
                    </span>
                  )}
                </button>
              </div>
            </form>
            
            {error && (
              <div className="mt-4 p-4 bg-danger-100 text-danger-700 rounded-md">
                <div className="flex items-center">
                  <FaExclamationTriangle className="mr-2 flex-shrink-0" />
                  <p>{error}</p>
                </div>
              </div>
            )}
            
            {loading && (
              <div className="mt-8">
                <Loading message="Analyzing URL and checking multiple verification services..." />
              </div>
            )}
            
            {result && !loading && (
              <div className="mt-8">
                <ResultCard result={result} />
                <div className="mt-4 text-center">
                  <Link href={`/analysis?url=${encodeURIComponent(formatUrl(url))}`} passHref>
                    <button className="btn btn-secondary">
                      <FaChartBar className="mr-2" />
                      View Detailed Analysis Report
                    </button>
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Feature Section */}
      <div className="py-12 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="lg:text-center">
            <h2 className="text-base text-primary-600 font-semibold tracking-wide uppercase">Features</h2>
            <p className="mt-2 text-3xl leading-8 font-extrabold tracking-tight text-gray-900 sm:text-4xl">
              Advanced Phishing Detection
            </p>
            <p className="mt-4 max-w-2xl text-xl text-gray-500 lg:mx-auto">
              Our system combines multiple verification methods to provide highly accurate phishing detection.
            </p>
          </div>

          <div className="mt-10">
            <div className="space-y-10 md:space-y-0 md:grid md:grid-cols-2 md:gap-x-8 md:gap-y-10">
              <div className="relative">
                <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-primary-500 text-white">
                  <FaShieldAlt className="h-6 w-6" />
                </div>
                <div className="ml-16">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Multiple Verification Methods</h3>
                  <p className="mt-2 text-base text-gray-500">
                    Combines ML models, PhishTank, Google Safe Browsing, and advanced heuristics for comprehensive detection.
                  </p>
                </div>
              </div>
              
              <div className="relative">
                <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-primary-500 text-white">
                  <FaCheck className="h-6 w-6" />
                </div>
                <div className="ml-16">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Detailed Explanations</h3>
                  <p className="mt-2 text-base text-gray-500">
                    Understand why a URL is flagged as phishing with human-readable explanations of suspicious characteristics.
                  </p>
                </div>
              </div>
              
              <div className="relative">
                <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-primary-500 text-white">
                  <FaShieldAlt className="h-6 w-6" />
                </div>
                <div className="ml-16">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Machine Learning Models</h3>
                  <p className="mt-2 text-base text-gray-500">
                    Two ML models analyze 45+ features including URL structure, domain age, character distributions, and more.
                  </p>
                </div>
              </div>
              
              <div className="relative">
                <div className="absolute flex items-center justify-center h-12 w-12 rounded-md bg-primary-500 text-white">
                  <FaCheck className="h-6 w-6" />
                </div>
                <div className="ml-16">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Real-time API Verification</h3>
                  <p className="mt-2 text-base text-gray-500">
                    Cross-verifies with PhishTank and Google Safe Browsing APIs to catch newly reported phishing URLs.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default Home;
