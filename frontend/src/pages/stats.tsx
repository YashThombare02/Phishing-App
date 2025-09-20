import React, { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import { getStatistics } from '@/utils/api';
import Loading from '@/components/Loading';
import { FaChartBar, FaExclamationTriangle, FaGlobe } from 'react-icons/fa';

interface Statistics {
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

const StatisticsPage: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<Statistics | null>(null);

  useEffect(() => {
    const fetchStatistics = async () => {
      try {
        const data = await getStatistics();
        setStats(data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'An error occurred while fetching statistics');
      } finally {
        setLoading(false);
      }
    };

    fetchStatistics();
  }, []);

  const renderTLDChart = () => {
    if (!stats?.common_tlds) return null;
    
    // Sort TLDs by count (descending)
    const sortedTLDs = Object.entries(stats.common_tlds)
      .sort(([, countA], [, countB]) => countB - countA)
      .slice(0, 10); // Take top 10
    
    const maxCount = Math.max(...sortedTLDs.map(([, count]) => count));
    
    return (
      <div className="mt-4">
        <h3 className="text-lg font-medium text-gray-900 mb-2">Top 10 TLDs in Analyzed URLs</h3>
        <div className="space-y-2">
          {sortedTLDs.map(([tld, count]) => (
            <div key={tld} className="flex items-center">
              <div className="w-20 text-sm font-medium text-gray-700">.{tld}</div>
              <div className="flex-1 h-6 bg-gray-200 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary-500 rounded-full"
                  style={{ width: `${(count / maxCount) * 100}%` }}
                />
              </div>
              <div className="w-12 text-right text-sm text-gray-700 ml-2">{count}</div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <Layout activePage="stats">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900">
            Detection Statistics
          </h1>
          <p className="mt-3 max-w-2xl mx-auto text-lg text-gray-500">
            View statistics and insights from all URL analyses performed by our system.
          </p>
        </div>

        {loading && (
          <div className="mt-8">
            <Loading message="Loading statistics..." />
          </div>
        )}

        {error && (
          <div className="mt-6 p-4 bg-danger-100 text-danger-700 rounded-md">
            <div className="flex items-center">
              <FaExclamationTriangle className="mr-2 flex-shrink-0" />
              <p>{error}</p>
            </div>
          </div>
        )}

        {stats && !loading && (
          <div className="mt-10 max-w-5xl mx-auto">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-primary-100 rounded-md p-3">
                      <FaGlobe className="h-6 w-6 text-primary-600" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        Total URLs Analyzed
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-gray-900">
                          {stats.total_urls_analyzed.toLocaleString()}
                        </div>
                      </dd>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-danger-100 rounded-md p-3">
                      <FaExclamationTriangle className="h-6 w-6 text-danger-600" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        Phishing URLs Detected
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-gray-900">
                          {stats.total_phishing.toLocaleString()}
                        </div>
                        <div className="ml-2 text-sm font-medium text-danger-600">
                          {stats.phishing_percentage.toFixed(1)}%
                        </div>
                      </dd>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-success-100 rounded-md p-3">
                      <FaGlobe className="h-6 w-6 text-success-600" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        Legitimate URLs
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-gray-900">
                          {stats.total_legitimate.toLocaleString()}
                        </div>
                        <div className="ml-2 text-sm font-medium text-success-600">
                          {stats.legitimate_percentage.toFixed(1)}%
                        </div>
                      </dd>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="px-4 py-5 sm:p-6">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 bg-primary-100 rounded-md p-3">
                      <FaChartBar className="h-6 w-6 text-primary-600" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        Detection Rate
                      </dt>
                      <dd className="flex items-baseline">
                        <div className="text-2xl font-semibold text-gray-900">
                          {(stats.phishing_percentage / 100).toLocaleString(undefined, {
                            style: 'percent',
                            minimumFractionDigits: 1,
                            maximumFractionDigits: 1,
                          })}
                        </div>
                      </dd>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Charts */}
            <div className="mt-8 bg-white shadow rounded-lg p-6">
              <h2 className="text-xl font-bold text-gray-900 mb-4">URL Analysis Breakdown</h2>
              
              <div className="flex justify-center mb-6">
                <div className="relative h-64 w-64">
                  {/* Simple pie chart visualization */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    <svg viewBox="0 0 36 36" className="h-full w-full">
                      <circle 
                        cx="18" 
                        cy="18" 
                        r="15.91549430918954" 
                        fill="transparent" 
                        stroke="#d1d5db" 
                        strokeWidth="3" 
                      />
                      <circle 
                        cx="18" 
                        cy="18" 
                        r="15.91549430918954" 
                        fill="transparent" 
                        stroke="#ef4444" 
                        strokeWidth="3" 
                        strokeDasharray={`${stats.phishing_percentage} ${100 - stats.phishing_percentage}`}
                        strokeDashoffset="25" 
                      />
                    </svg>
                    <div className="absolute flex flex-col items-center justify-center">
                      <span className="text-3xl font-bold">{stats.phishing_percentage.toFixed(1)}%</span>
                      <span className="text-sm text-gray-500">Phishing</span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {renderTLDChart()}
                
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Recent Detections</h3>
                  {stats.recent_detections && stats.recent_detections.length > 0 ? (
                    <ul className="divide-y divide-gray-200">
                      {stats.recent_detections.map((detection, index) => (
                        <li key={index} className="py-3">
                          <div className="flex items-center">
                            <div className={`w-2 h-2 rounded-full mr-3 ${detection.is_phishing ? 'bg-danger-500' : 'bg-success-500'}`}></div>
                            <div className="flex-1 truncate">
                              <p className="text-sm font-medium text-gray-900 truncate">{detection.url}</p>
                              <p className="text-xs text-gray-500">
                                {new Date(detection.timestamp).toLocaleString()}
                              </p>
                            </div>
                            <div className={`px-2 py-1 text-xs rounded-full ${detection.is_phishing ? 'bg-danger-100 text-danger-800' : 'bg-success-100 text-success-800'}`}>
                              {detection.is_phishing ? 'Phishing' : 'Safe'}
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-gray-500">No recent detections found.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default StatisticsPage;
