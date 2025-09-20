import React, { useState } from 'react';
import Layout from '@/components/Layout';
import { reportPhishingSite } from '@/utils/api';
import { isValidUrl, formatUrl } from '@/utils/urlUtils';
import { FaExclamationTriangle, FaCheckCircle, FaLink } from 'react-icons/fa';
import Link from 'next/link';

const ReportPage: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);

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
      await reportPhishingSite(formattedUrl, description);
      setSuccess(true);
      // Clear form
      setUrl('');
      setDescription('');
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
          <h1 className="text-3xl font-bold text-gray-900">
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
                  <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-1">
                    Phishing URL <span className="text-red-500">*</span>
                  </label>
                  <div className="mt-1 flex rounded-md shadow-sm">
                    <span className="inline-flex items-center px-3 rounded-l-md border border-r-0 border-gray-300 bg-gray-50 text-gray-500">
                      <FaLink className="h-4 w-4" />
                    </span>
                    <input
                      type="text"
                      id="url"
                      name="url"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="focus:ring-blue-500 focus:border-blue-500 flex-1 block w-full rounded-none rounded-r-md sm:text-sm border-gray-300"
                      placeholder="https://suspicious-website.com"
                      required
                    />
                  </div>
                </div>

                <div className="mb-6">
                  <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
                    Description (Optional)
                  </label>
                  <textarea
                    id="description"
                    name="description"
                    rows={4}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="focus:ring-blue-500 focus:border-blue-500 block w-full rounded-md sm:text-sm border-gray-300"
                    placeholder="Please provide any additional information about this phishing site, such as what legitimate site it's trying to imitate, how you found it, etc."
                  ></textarea>
                </div>

                <div className="px-4 py-3 bg-gray-50 text-right sm:px-6">
                  <button
                    type="submit"
                    className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    disabled={loading}
                  >
                    {loading ? (
                      <span className="flex items-center">
                        <span className="animate-spin h-4 w-4 mr-2 border-2 border-white border-t-transparent rounded-full"></span>
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

          <div className="mt-10 bg-gray-50 p-6 rounded-lg">
            <h2 className="text-lg font-medium text-gray-900 mb-4">What to Report</h2>
            <ul className="space-y-2 text-gray-600">
              <li className="flex items-start">
                <span className="text-blue-500 mr-2">•</span>
                <span>Websites impersonating legitimate services (banks, email providers, social media, etc.)</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-500 mr-2">•</span>
                <span>Sites asking for personal information, passwords, or financial details</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-500 mr-2">•</span>
                <span>Suspicious login pages that don't match the official website's appearance</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-500 mr-2">•</span>
                <span>Sites with suspicious URLs that mimic legitimate domains</span>
              </li>
            </ul>

            <h2 className="text-lg font-medium text-gray-900 mt-6 mb-4">What Happens Next</h2>
            <p className="text-gray-600">
              Our team will review your report and verify the URL. If confirmed as a phishing site, 
              we'll add it to our database and improve our detection algorithms. This helps protect 
              other users from similar threats. We may also report confirmed phishing sites to 
              relevant authorities and browser safety services.
            </p>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default ReportPage;
