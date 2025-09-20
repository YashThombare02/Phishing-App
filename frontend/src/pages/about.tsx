import React from 'react';
import Layout from '@/components/Layout';
import { FaShieldAlt, FaCode, FaDatabase, FaRobot, FaSearch, FaBug } from 'react-icons/fa';

const AboutPage: React.FC = () => {
  return (
    <Layout activePage="about">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900">
            About PhishGuard
          </h1>
          <p className="mt-3 max-w-3xl mx-auto text-lg text-gray-500">
            PhishGuard is a comprehensive phishing detection system that combines machine learning, 
            real-time API verification, and advanced URL analysis to protect users from phishing attacks.
          </p>
        </div>

        <div className="mt-12 max-w-5xl mx-auto">
          <div className="prose prose-blue mx-auto lg:max-w-none">
            <h2>Our Mission</h2>
            <p>
              The internet is filled with deceptive websites designed to steal personal information.
              Our mission is to provide a reliable, accessible tool that helps users identify potential
              phishing attempts before they become victims. By combining multiple detection methods,
              we offer a robust defense against increasingly sophisticated phishing attacks.
            </p>

            <h2>How It Works</h2>
            <p>
              PhishGuard employs a multi-layered approach to detect phishing URLs:
            </p>

            <div className="mt-8 grid gap-8 grid-cols-1 md:grid-cols-2">
              <div className="relative bg-white p-6 rounded-lg shadow-md">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-primary-500 flex items-center justify-center">
                  <FaRobot className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 pl-8 pt-2 mb-4">Machine Learning Models</h3>
                <p className="text-gray-600">
                  Our system uses advanced machine learning models trained on thousands of known phishing and legitimate URLs.
                  The models analyze URL structure, lexical features, and other patterns to identify potential threats.
                </p>
              </div>

              <div className="relative bg-white p-6 rounded-lg shadow-md">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-primary-500 flex items-center justify-center">
                  <FaSearch className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 pl-8 pt-2 mb-4">Real-time API Verification</h3>
                <p className="text-gray-600">
                  We integrate with trusted services like PhishTank and Google Safe Browsing to cross-reference URLs
                  against constantly updated databases of known phishing sites.
                </p>
              </div>

              <div className="relative bg-white p-6 rounded-lg shadow-md">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-primary-500 flex items-center justify-center">
                  <FaCode className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 pl-8 pt-2 mb-4">Content Analysis</h3>
                <p className="text-gray-600">
                  Our system can analyze webpage content to detect suspicious elements commonly found in phishing sites,
                  such as login forms, brand imitations, and security indicators.
                </p>
              </div>

              <div className="relative bg-white p-6 rounded-lg shadow-md">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-primary-500 flex items-center justify-center">
                  <FaDatabase className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 pl-8 pt-2 mb-4">WHOIS & Domain Analysis</h3>
                <p className="text-gray-600">
                  We examine domain registration data, age, reputation, and hosting information to identify
                  recently created or suspicious domains often associated with phishing campaigns.
                </p>
              </div>
            </div>

            <h2 className="mt-12">Features</h2>
            <ul className="space-y-2">
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span><strong>Real-time URL Analysis:</strong> Check any URL instantly through our web interface.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span><strong>Batch Processing:</strong> Check multiple URLs at once for efficient scanning.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span><strong>Detailed Reports:</strong> Get comprehensive analysis explaining why a URL was flagged.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span><strong>API Access:</strong> Integrate our detection system into your own applications and services.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span><strong>Statistics Dashboard:</strong> View trends and insights from our phishing detection system.</span>
              </li>
            </ul>

            <h2 className="mt-12">Technical Implementation</h2>
            <p>
              PhishGuard is built with modern web technologies:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-900 mb-2">Frontend</h3>
                <ul className="space-y-1 text-gray-600">
                  <li>• Next.js and React</li>
                  <li>• TypeScript for type safety</li>
                  <li>• TailwindCSS for responsive design</li>
                  <li>• Axios for API requests</li>
                </ul>
              </div>

              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-900 mb-2">Backend</h3>
                <ul className="space-y-1 text-gray-600">
                  <li>• Flask API</li>
                  <li>• Scikit-learn and XGBoost for ML models</li>
                  <li>• BeautifulSoup for content analysis</li>
                  <li>• External API integrations</li>
                </ul>
              </div>
            </div>

            <h2 className="mt-12">Privacy Commitment</h2>
            <p>
              We take privacy seriously. When you submit a URL for analysis:
            </p>
            <ul className="space-y-2">
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span>We only store the URL and analysis results for improving our detection system</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span>We don't track your personal information</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-primary-500 mr-2">
                  <FaShieldAlt />
                </span>
                <span>We don't share your submitted URLs with third parties except as required for analysis</span>
              </li>
            </ul>

            <div className="mt-12 bg-primary-50 p-6 rounded-lg">
              <h2 className="text-primary-800 mb-4">Report Phishing Sites</h2>
              <p className="text-primary-700">
                Found a phishing site that our system missed? Help improve our detection by reporting it.
                Together we can make the internet safer for everyone.
              </p>
              <div className="mt-4">
                <a 
                  href="/report" 
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                >
                  <FaBug className="mr-2 -ml-1 h-5 w-5" />
                  Report a Phishing Site
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default AboutPage;
