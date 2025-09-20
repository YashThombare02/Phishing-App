import React, { useState } from 'react';
import Layout from '@/components/Layout';
import { batchDetectUrls } from '@/utils/api';
import { isValidUrl, formatUrl } from '@/utils/urlUtils';
import ResultCard from '@/components/ResultCard';
import Loading from '@/components/Loading';
import { FaSearch, FaUpload, FaExclamationTriangle } from 'react-icons/fa';

const BatchAnalysis: React.FC = () => {
  const [urls, setUrls] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<any[]>([]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Reset states
    setError(null);
    setResults([]);
    
    // Validate URLs
    if (!urls.trim()) {
      setError('Please enter at least one URL');
      return;
    }
    
    // Parse URLs (one per line)
    const urlList = urls
      .split('\n')
      .map(url => url.trim())
      .filter(url => url !== '');
    
    if (urlList.length === 0) {
      setError('Please enter at least one valid URL');
      return;
    }
    
    // Format and validate URLs
    const formattedUrls = urlList.map(url => formatUrl(url));
    const invalidUrls = formattedUrls.filter(url => !isValidUrl(url));
    
    if (invalidUrls.length > 0) {
      setError(`Found ${invalidUrls.length} invalid URL(s). Please check your input.`);
      return;
    }
    
    // Start loading
    setLoading(true);
    
    try {
      // Call API
      const data = await batchDetectUrls(formattedUrls);
      setResults(data.results || []);
    } catch (err: any) {
      setError(err.response?.data?.error || 'An error occurred while analyzing the URLs');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    
    if (!file) {
      return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setUrls(content || '');
    };
    
    reader.onerror = () => {
      setError('Error reading file');
    };
    
    reader.readAsText(file);
  };

  return (
    <Layout activePage="batch">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900">
            Batch URL Analysis
          </h1>
          <p className="mt-3 max-w-2xl mx-auto text-lg text-gray-500">
            Analyze multiple URLs at once. Enter one URL per line or upload a text file.
          </p>
        </div>

        <div className="mt-10 max-w-4xl mx-auto">
          <form onSubmit={handleSubmit}>
            <div className="shadow overflow-hidden sm:rounded-md">
              <div className="px-4 py-5 bg-white sm:p-6">
                <div>
                  <label htmlFor="urls" className="block text-sm font-medium text-gray-700 mb-2">
                    URLs (one per line)
                  </label>
                  <textarea
                    id="urls"
                    name="urls"
                    rows={10}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                    placeholder="https://example.com&#10;https://anotherexample.com"
                    value={urls}
                    onChange={(e) => setUrls(e.target.value)}
                  ></textarea>
                </div>
                
                <div className="mt-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Or upload a text file
                  </label>
                  <div className="flex items-center">
                    <label htmlFor="file-upload" className="btn btn-outline flex items-center cursor-pointer">
                      <FaUpload className="mr-2" />
                      Upload File
                    </label>
                    <input
                      id="file-upload"
                      name="file-upload"
                      type="file"
                      accept=".txt"
                      className="sr-only"
                      onChange={handleFileUpload}
                    />
                    <span className="ml-3 text-sm text-gray-500">
                      Text file (.txt) with one URL per line
                    </span>
                  </div>
                </div>
              </div>
              <div className="px-4 py-3 bg-gray-50 text-right sm:px-6">
                <button
                  type="submit"
                  className="btn btn-primary"
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
                      Analyze URLs
                    </span>
                  )}
                </button>
              </div>
            </div>
          </form>
          
          {error && (
            <div className="mt-6 p-4 bg-danger-100 text-danger-700 rounded-md">
              <div className="flex items-center">
                <FaExclamationTriangle className="mr-2 flex-shrink-0" />
                <p>{error}</p>
              </div>
            </div>
          )}
          
          {loading && (
            <div className="mt-8">
              <Loading message="Analyzing URLs in batch. This may take a few moments..." />
            </div>
          )}
          
          {results.length > 0 && !loading && (
            <div className="mt-8">
              <h2 className="text-xl font-bold text-gray-900 mb-4">Results ({results.length} URLs)</h2>
              
              <div className="mb-4 p-4 bg-gray-50 rounded-md">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-700">
                      <span className="font-medium">Phishing URLs: </span>
                      {results.filter(r => r.final_verdict).length}
                    </p>
                    <p className="text-sm text-gray-700">
                      <span className="font-medium">Safe URLs: </span>
                      {results.filter(r => !r.final_verdict).length}
                    </p>
                  </div>
                </div>
              </div>
              
              {results.map((result, index) => (
                <ResultCard key={index} result={result} />
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default BatchAnalysis;
