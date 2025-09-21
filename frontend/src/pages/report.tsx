import React, { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import { reportPhishingSite, getReports, Report } from '@/utils/api';
import { isValidUrl, formatUrl } from '@/utils/urlUtils';
import { FaExclamationTriangle, FaCheckCircle, FaLink, FaUser, FaSpinner, FaChevronLeft, FaChevronRight } from 'react-icons/fa';
import Link from 'next/link';

const ReportPage: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [username, setUsername] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);
  
  // Reports table state
  const [reports, setReports] = useState<Report[]>([]);
  const [page, setPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [fetchingReports, setFetchingReports] = useState<boolean>(false);
  const [reportsError, setReportsError] = useState<string | null>(null);

  // Fetch reports on component mount and when page changes
  useEffect(() => {
    fetchReports();
  }, [page]);

  const fetchReports = async () => {
    setFetchingReports(true);
    setReportsError(null);
    
    try {
      console.log('Fetching reports for page:', page);
      const response = await getReports(page, 10);
      
      setReports(response.reports);
      setTotalPages(response.total_pages);
      setTotalRecords(response.total_records);
    } catch (error: any) {
      console.error('Error fetching reports:', error);
      setReportsError('Failed to fetch reports. Please try again later.');
    } finally {
      setFetchingReports(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Reset states
    setError(null);
    setSuccess(false);
    
    // Validate URL
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }
    
    const formattedUrl = formatUrl(url);
    if (!isValidUrl(formattedUrl)) {
      setError('Please enter a valid URL');
      return;
    }
    
    // Start loading
    setLoading(true);
    
    try {
      // Call API
      await reportPhishingSite(formattedUrl, username, description);
      setSuccess(true);
      // Clear form
      setUrl('');
      setUsername('');
      setDescription('');
      // Refresh reports
      fetchReports();
    } catch (err: any) {
      setError(err.response?.data?.error || 'An error occurred while submitting your report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout activePage="report">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-white font-cyber">
            Report a Phishing Site
          </h1>
          <p className="mt-3 max-w-2xl mx-auto text-lg text-gray-500">
            Help improve our phishing detection system by reporting URLs that you believe are phishing sites.
          </p>
        </div>

        <div className="mt-10 max-w-3xl mx-auto">
          {success ? (
            <div className="bg-green-50 p-6 rounded-lg shadow-md">
              <div className="flex items-center">
                <FaCheckCircle className="h-8 w-8 text-green-500 mr-4" />
                <div>
                  <h2 className="text-xl font-medium text-green-800">Thank You for Your Report</h2>
                  <p className="mt-2 text-green-700">
                    Your report has been submitted successfully. Our team will review it as soon as possible.
                    Your contribution helps make the internet safer for everyone.
                  </p>
                  <div className="mt-4 flex space-x-4">
                    <button
                      onClick={() => setSuccess(false)}
                      className="px-4 py-2 border border-green-500 text-green-500 rounded-md hover:bg-green-50"
                    >
                      Report Another Site
                    </button>
                    <Link href="/analysis" passHref>
                      <button
                        className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                      >
                        Analyze a URL
                      </button>
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="shadow overflow-hidden sm:rounded-md">
              <div className="px-4 py-5 bg-white sm:p-6">
                {error && (
                  <div className="mb-6 p-4 bg-red-100 text-red-700 rounded-md">
                    <div className="flex items-center">
                      <FaExclamationTriangle className="mr-2 flex-shrink-0" />
                      <p>{error}</p>
                    </div>
                  </div>
                )}

                <div className="mb-6">
                  <label htmlFor="url" className="block text-base font-medium text-gray-800 mb-2">
                    Phishing URL <span className="text-red-500">*</span>
                  </label>
                  <div className="mt-1 flex rounded-md shadow-sm">
                    <span className="inline-flex items-center px-4 rounded-l-md border-2 border-r-0 border-gray-300 bg-gray-50 text-gray-600">
                      <FaLink className="h-5 w-5" />
                    </span>
                    <input
                      type="text"
                      id="url"
                      name="url"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="focus:ring-blue-500 focus:border-blue-500 flex-1 block w-full py-3 px-4 rounded-none rounded-r-md text-base border-2 border-gray-300 text-gray-900 hover:border-blue-400"
                      placeholder="https://suspicious-website.com"
                      required
                    />
                  </div>
                </div>

                <div className="mb-6">
                  <label htmlFor="username" className="block text-base font-medium text-gray-800 mb-2">
                    Your Name
                  </label>
                  <div className="mt-1 flex rounded-md shadow-sm">
                    <span className="inline-flex items-center px-4 rounded-l-md border-2 border-r-0 border-gray-300 bg-gray-50 text-gray-600">
                      <FaUser className="h-5 w-5" />
                    </span>
                    <input
                      type="text"
                      id="username"
                      name="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="focus:ring-blue-500 focus:border-blue-500 flex-1 block w-full py-3 px-4 rounded-none rounded-r-md text-base border-2 border-gray-300 text-gray-900 hover:border-blue-400"
                      placeholder="Your name (optional)"
                    />
                  </div>
                </div>

                <div className="mb-6">
                  <label htmlFor="description" className="block text-base font-medium text-gray-800 mb-2">
                    Description (Optional)
                  </label>
                  <textarea
                    id="description"
                    name="description"
                    rows={4}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="focus:ring-blue-500 focus:border-blue-500 block w-full rounded-md py-3 px-4 text-base border-2 border-gray-300 text-gray-900 hover:border-blue-400"
                    placeholder="Please provide any additional information about this phishing site, such as what legitimate site it's trying to imitate, how you found it, etc."
                  ></textarea>
                </div>

                <div className="px-4 py-4 bg-gray-50 text-right sm:px-6">
                  <button
                    type="submit"
                    className="inline-flex justify-center py-3 px-6 border border-transparent shadow-sm text-base font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    disabled={loading}
                  >
                    {loading ? (
                      <span className="flex items-center">
                        <span className="animate-spin h-5 w-5 mr-3 border-2 border-white border-t-transparent rounded-full"></span>
                        Submitting...
                      </span>
                    ) : (
                      <span>Submit Report</span>
                    )}
                  </button>
                </div>
              </div>
            </form>
          )}
        </div>
        
        {/* Reports Table Section */}
        <div className="mt-8 max-w-7xl mx-auto">
          <div className="pb-5 border-b border-gray-200">
            <h2 className="text-2xl font-bold text-white font-cyber">
              Submitted Phishing Reports
            </h2>
            <p className="mt-2 text-sm text-gray-400">
              These reported URLs have been marked as phishing sites based on user submissions.
            </p>
          </div>
          
          {reportsError ? (
            <div className="mt-4 bg-red-50 p-4 rounded-md">
              <div className="flex">
                <div className="flex-shrink-0">
                  <FaExclamationTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Error loading reports</h3>
                  <p className="mt-2 text-sm text-red-700">{reportsError}</p>
                  <button
                    onClick={fetchReports}
                    className="mt-2 px-3 py-1 text-sm font-medium text-red-700 hover:text-red-600 bg-red-100 hover:bg-red-200 rounded-md"
                  >
                    Try Again
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-8 bg-white shadow overflow-hidden rounded-lg">
              {fetchingReports && reports.length === 0 ? (
                <div className="flex justify-center items-center h-40">
                  <FaSpinner className="h-8 w-8 text-blue-500 animate-spin mr-2" />
                  <span className="text-gray-600">Loading reports...</span>
                </div>
              ) : reports.length === 0 ? (
                <div className="px-4 py-5 sm:p-6 text-center text-gray-500">
                  <p>No phishing reports have been submitted yet.</p>
                </div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            ID
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            URL
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Reported By
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Date
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Status
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {reports.map((report) => (
                          <tr key={report.id} className="hover:bg-gray-50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                              #{report.id}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-500 hover:text-blue-700 hover:underline">
                              <a 
                                href={report.url} 
                                target="_blank" 
                                rel="noopener noreferrer" 
                                title={report.url}
                                className="block max-w-xs truncate"
                              >
                                {report.url}
                              </a>
                              <span className="text-xs text-gray-500 block">{report.domain}</span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {report.username || 'Anonymous'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {report.timestamp || 'N/A'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                ${report.status === 'verified' ? 'bg-green-100 text-green-800' : 
                                  report.status === 'rejected' ? 'bg-red-100 text-red-800' : 
                                  report.status === 'phishing' ? 'bg-red-100 text-red-800' :
                                  'bg-yellow-100 text-yellow-800'}`}>
                                {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  
                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
                      <div className="flex-1 flex justify-between sm:hidden">
                        <button
                          onClick={() => setPage(Math.max(page - 1, 1))}
                          disabled={page === 1}
                          className={`relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md ${
                            page === 1 ? 'bg-gray-50 text-gray-400 cursor-not-allowed' : 'bg-white text-gray-700 hover:bg-gray-50'
                          }`}
                        >
                          Previous
                        </button>
                        <button
                          onClick={() => setPage(Math.min(page + 1, totalPages))}
                          disabled={page === totalPages}
                          className={`ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md ${
                            page === totalPages ? 'bg-gray-50 text-gray-400 cursor-not-allowed' : 'bg-white text-gray-700 hover:bg-gray-50'
                          }`}
                        >
                          Next
                        </button>
                      </div>
                      <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                        <div>
                          <p className="text-sm text-gray-700">
                            Showing <span className="font-medium">{(page - 1) * 10 + 1}</span> to{' '}
                            <span className="font-medium">{Math.min(page * 10, totalRecords)}</span> of{' '}
                            <span className="font-medium">{totalRecords}</span> results
                          </p>
                        </div>
                        <div>
                          <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                            <button
                              onClick={() => setPage(Math.max(page - 1, 1))}
                              disabled={page === 1}
                              className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
                            >
                              <span className="sr-only">Previous</span>
                              <FaChevronLeft className="h-5 w-5" />
                            </button>
                            
                            {/* Page numbers */}
                            {Array.from({ length: Math.min(5, totalPages) }).map((_, i) => {
                              let pageNum;
                              
                              if (totalPages <= 5) {
                                pageNum = i + 1;
                              } else if (page <= 3) {
                                pageNum = i + 1;
                              } else if (page >= totalPages - 2) {
                                pageNum = totalPages - 4 + i;
                              } else {
                                pageNum = page - 2 + i;
                              }
                              
                              return (
                                <button
                                  key={pageNum}
                                  onClick={() => setPage(pageNum)}
                                  className={`relative inline-flex items-center px-4 py-2 border ${
                                    page === pageNum
                                      ? 'z-10 bg-blue-50 border-blue-500 text-blue-600'
                                      : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
                                  } text-sm font-medium`}
                                >
                                  {pageNum}
                                </button>
                              );
                            })}
                            
                            <button
                              onClick={() => setPage(Math.min(page + 1, totalPages))}
                              disabled={page === totalPages}
                              className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
                            >
                              <span className="sr-only">Next</span>
                              <FaChevronRight className="h-5 w-5" />
                            </button>
                          </nav>
                        </div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default ReportPage;
