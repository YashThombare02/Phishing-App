import React from 'react';
import Layout from '@/components/Layout';
import { FaShieldAlt, FaCode, FaDatabase, FaRobot, FaSearch, FaBug, FaLock, FaNetworkWired, FaExclamationTriangle, FaFingerprint } from 'react-icons/fa';

const AboutPage: React.FC = () => {
  return (
    <Layout activePage="about">
      <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-white font-cyber">
            About PhishGuard
          </h1>
          <p className="mt-3 max-w-3xl mx-auto text-lg text-gray-300">
            A comprehensive phishing detection system that combines machine learning, 
            domain analysis, and trusted third-party verifications to create a multi-layered defense system.
          </p>
        </div>

        <div className="mt-12 max-w-5xl mx-auto">
          <div className="prose prose-invert mx-auto lg:max-w-none">
            <h2 className="text-cyber-accent font-cyber">Our Mission</h2>
            <p>
              The internet is full of deceptive websites created to steal personal information. PhishGuard's mission is to provide a reliable, user-friendly tool to help people identify phishing websites before they fall victim.
              By combining advanced machine learning, domain analysis, and trusted third-party verifications, we create a multi-layered defense system against phishing attacks.
            </p>

            <h2 className="text-cyber-accent font-cyber">How It Works</h2>
            <p>
              PhishGuard analyzes every submitted URL through several stages of verification:
            </p>

            <div className="mt-8 grid gap-8 grid-cols-1 md:grid-cols-2">
              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaRobot className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">Machine Learning Models</h3>
                <p className="text-gray-300">
                  We employ Random Forest and XGBoost algorithms trained on thousands 
                  of verified phishing URLs to detect subtle patterns invisible to humans.
                </p>
              </div>

              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaFingerprint className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">Homograph Attack Detection</h3>
                <p className="text-gray-300">
                  Our system uses character skeletonization techniques to identify visually similar but 
                  different characters often used to impersonate legitimate domains.
                </p>
              </div>

              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaSearch className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">External API Verification</h3>
                <p className="text-gray-300">
                  We integrate with PhishTank and Google Safe Browsing APIs to cross-reference URLs 
                  against constantly updated databases of known threats.
                </p>
              </div>

              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaNetworkWired className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">Domain Reliability Checks</h3>
                <p className="text-gray-300">
                  We analyze WHOIS data, SSL certificate validity, DNS records, and domain age 
                  to verify legitimacy and detect recently created phishing domains.
                </p>
              </div>
              
              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaExclamationTriangle className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">Anomaly Detection</h3>
                <p className="text-gray-300">
                  Using Isolation Forest algorithms, we identify URLs with unusual characteristics 
                  that deviate from normal patterns, catching new phishing techniques.
                </p>
              </div>

              <div className="relative bg-cyber-dark-800 p-6 rounded-lg shadow-md border border-cyber-accent">
                <div className="absolute -top-4 -left-4 w-12 h-12 rounded-full bg-cyber-accent flex items-center justify-center">
                  <FaBug className="h-6 w-6 text-cyber-dark" />
                </div>
                <h3 className="text-lg font-medium text-cyber-accent pl-8 pt-2 mb-4">Content Analysis</h3>
                <p className="text-gray-300">
                  For suspicious URLs, we analyze page content to detect login forms, 
                  obfuscated scripts, brand impersonation, and credential harvesting attempts.
                </p>
              </div>
            </div>

            <h2 className="mt-12 text-cyber-accent font-cyber">Features</h2>
            <ul className="space-y-2">
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaShieldAlt />
                </span>
                <span className="text-gray-300"><strong className="text-white">Real-time URL Analysis:</strong> Check any URL instantly through our secure web interface.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaShieldAlt />
                </span>
                <span className="text-gray-300"><strong className="text-white">Batch Processing:</strong> Check multiple URLs at once for efficient scanning of email links or suspicious messages.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaShieldAlt />
                </span>
                <span className="text-gray-300"><strong className="text-white">Detailed Security Reports:</strong> Get comprehensive analysis explaining why a URL was flagged with specific threat indicators.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaShieldAlt />
                </span>
                <span className="text-gray-300"><strong className="text-white">Dashboard & Statistics:</strong> View trends and insights into phishing attacks with our real-time analytics dashboard.</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaShieldAlt />
                </span>
                <span className="text-gray-300"><strong className="text-white">API Access:</strong> Integrate our detection system into your own applications and security services.</span>
              </li>
            </ul>

            <h2 className="mt-12 text-cyber-accent font-cyber">Technology Stack</h2>
            <p className="text-gray-300">
              PhishGuard is built with modern technologies for maximum security and performance:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
              <div className="bg-cyber-dark-800 p-4 rounded-lg border border-cyber-accent">
                <h3 className="font-medium text-cyber-accent mb-2">Frontend</h3>
                <ul className="space-y-1 text-gray-300">
                  <li>• Next.js and React for dynamic UI</li>
                  <li>• TailwindCSS for responsive design</li>
                  <li>• Chart.js for data visualization</li>
                  <li>• TypeScript for type safety</li>
                </ul>
              </div>

              <div className="bg-cyber-dark-800 p-4 rounded-lg border border-cyber-accent">
                <h3 className="font-medium text-cyber-accent mb-2">Backend</h3>
                <ul className="space-y-1 text-gray-300">
                  <li>• Flask API with SQLAlchemy</li>
                  <li>• Scikit-learn and XGBoost ML models</li>
                  <li>• NumPy and Pandas for data processing</li>
                  <li>• BeautifulSoup for content analysis</li>
                </ul>
              </div>
              
              <div className="bg-cyber-dark-800 p-4 rounded-lg border border-cyber-accent">
                <h3 className="font-medium text-cyber-accent mb-2">Libraries & Tools</h3>
                <ul className="space-y-1 text-gray-300">
                  <li>• Levenshtein for string similarity detection</li>
                  <li>• DNS resolver for domain verification</li>
                  <li>• IP geolocation services</li>
                  <li>• SSL certificate analyzers</li>
                </ul>
              </div>
              
              <div className="bg-cyber-dark-800 p-4 rounded-lg border border-cyber-accent">
                <h3 className="font-medium text-cyber-accent mb-2">External APIs</h3>
                <ul className="space-y-1 text-gray-300">
                  <li>• PhishTank for known phishing sites</li>
                  <li>• Google Safe Browsing API</li>
                  <li>• WHOIS data providers</li>
                  <li>• Threat intelligence feeds</li>
                </ul>
              </div>
            </div>

            <h2 className="mt-12 text-cyber-accent font-cyber">Privacy Commitment</h2>
            <p className="text-gray-300">
              We take your privacy and security seriously. When you submit a URL for analysis:
            </p>
            <ul className="space-y-2">
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaLock />
                </span>
                <span className="text-gray-300">All analysis is performed securely on our servers, not in your browser</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaLock />
                </span>
                <span className="text-gray-300">We do not collect any personal data from your browsing session</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaLock />
                </span>
                <span className="text-gray-300">Submitted URLs are stored only for system improvement and research purposes</span>
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 h-6 w-6 text-cyber-accent mr-2">
                  <FaLock />
                </span>
                <span className="text-gray-300">We never share your submitted URLs with third-parties for marketing or tracking</span>
              </li>
            </ul>

            <div className="mt-12 bg-cyber-dark-800 p-6 rounded-lg border border-cyber-accent">
              <h2 className="text-cyber-accent mb-4 font-cyber">Report Phishing Sites</h2>
              <p className="text-gray-300">
                Found a phishing site that our system missed? Help improve our detection by reporting it.
                Together we can make the internet safer for everyone.
              </p>
              <div className="mt-4">
                <a 
                  href="/report" 
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-cyber-dark bg-cyber-accent hover:bg-cyber-accent-bright focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-accent"
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
