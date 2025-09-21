import React from 'react';
import { FaExclamationTriangle, FaCheckCircle, FaShieldAlt, FaGlobe, FaLink, FaLock, FaUnlock } from 'react-icons/fa';

interface PhishingReportProps {
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

const PhishingAnalysisReport: React.FC<PhishingReportProps> = ({
  url,
  isPhishing,
  score,
  reasons = [], // Default to empty array if undefined
  features = {
    domain: '',
    subdomain: '',
    domainName: '',
    tld: '',
    usesHttps: false,
    containsHyphens: false,
    containsNumbers: false,
    suspiciousTld: false,
    pathIndicators: []
  }, // Default with all required properties
  detailedAnalysis = {
    suspiciousElements: [],
    technicalDetails: []
  } // Default to empty arrays if undefined
}) => {
  // Calculate confidence (0-100%)
  // Ensure it's properly capped at 100% and rounded to avoid weird values
  const confidence = Math.min(parseFloat((Math.abs(score - 0.5) * 2 * 100).toFixed(2)), 100);
  
  // Determine severity class based on phishing score
  const getSeverityClass = () => {
    if (isPhishing) {
      return {
        bg: 'bg-cyber-dark',
        border: 'border-danger-500/50',
        heading: 'text-danger-400',
        text: 'text-danger-300',
        icon: 'text-danger-500',
        progressBar: 'bg-danger-500',
        lightBg: 'bg-danger-900/30'
      };
    } else {
      return {
        bg: 'bg-cyber-dark',
        border: 'border-success-500/50',
        heading: 'text-success-400',
        text: 'text-success-300',
        icon: 'text-success-500',
        progressBar: 'bg-success-500',
        lightBg: 'bg-success-900/30'
      };
    }
  };
  
  const severityClass = getSeverityClass();

  return (
    <div className={`rounded-lg shadow-cyber-glow overflow-hidden ${severityClass.bg} border ${severityClass.border}`}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center">
          {isPhishing ? (
            <FaExclamationTriangle className={`h-6 w-6 ${severityClass.icon} mr-3 animate-pulse`} />
          ) : (
            <FaShieldAlt className={`h-6 w-6 ${severityClass.icon} mr-3`} />
          )}
          <h2 className={`text-xl font-bold ${severityClass.heading} font-cyber`}>
            {isPhishing ? 'Phishing URL Detected' : 'Legitimate URL'}
          </h2>
        </div>
        <div className="text-right">
          <span className={`text-sm font-medium ${severityClass.text}`}>Confidence:</span>
          <div className="w-32 h-4 bg-gray-800 rounded-full mt-1 overflow-hidden">
            <div 
              className={`h-full ${severityClass.progressBar}`} 
              style={{ width: `${confidence}%` }}
            ></div>
          </div>
          <span className={`text-xs ${severityClass.text} font-semibold`}>{confidence}%</span>
        </div>
      </div>

      {/* URL Card */}
      <div className="px-6 py-4">
        <div className="bg-cyber-darker rounded-md p-3 border border-gray-700 mb-4 break-all shadow-cyber-glow">
          <div className="flex items-start">
            <div className="mt-1">
              {features.usesHttps ? (
                <FaLock className="h-4 w-4 text-success-500 mr-2" />
              ) : (
                <FaUnlock className="h-4 w-4 text-danger-500 mr-2" />
              )}
            </div>
            <div>
              <p className="text-gray-400 text-sm mb-1">URL</p>
              <p className="text-white font-medium">{url}</p>
              <p className="text-xs text-gray-500 mt-1">
                Analyzed on {new Date().toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        {/* Verdict Summary */}
        <div className={`p-4 ${severityClass.lightBg} rounded-md mb-4 border border-gray-700`}>
          <p className={`font-medium ${severityClass.heading}`}>
            {isPhishing
              ? `This URL has been classified as a phishing site with ${Math.min(Math.round(score * 100), 100)}% probability.`
              : `This URL appears to be legitimate with ${Math.min(Math.round((1 - score) * 100), 100)}% probability.`}
          </p>
        </div>

        {/* Domain Analysis */}
        <div className="mb-6">
          <h3 className="text-lg font-medium text-white font-cyber mb-3 flex items-center">
            <FaGlobe className="mr-2 text-cyber-accent" /> Domain Structure
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 shadow-cyber-glow">
              <p className="text-sm text-gray-400">Full Domain</p>
              <p className="font-medium text-white">{features.domain}</p>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 shadow-cyber-glow">
              <p className="text-sm text-gray-400">Subdomain</p>
              <p className="font-medium text-white">{features.subdomain || '(none)'}</p>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 shadow-cyber-glow">
              <p className="text-sm text-gray-400">Domain Name</p>
              <p className="font-medium text-white">{features.domainName}</p>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 shadow-cyber-glow">
              <p className="text-sm text-gray-400">TLD</p>
              <p className="font-medium text-white">.{features.tld}</p>
            </div>
          </div>
        </div>

        {/* Suspicious Elements */}
        <div className="mb-6">
          <h3 className="text-lg font-medium text-white font-cyber mb-3 flex items-center">
            <FaExclamationTriangle className="mr-2 text-cyber-warning" /> Key Findings
          </h3>
          <ul className="space-y-2 bg-cyber-darker p-4 rounded border border-gray-700 shadow-cyber-glow">
            {reasons.length > 0 ? (
              reasons.map((reason, index) => (
                <li key={index} className="flex items-start">
                  <FaExclamationTriangle className="h-5 w-5 text-cyber-warning mr-2 mt-0.5" />
                  <span className="text-gray-200">{reason}</span>
                </li>
              ))
            ) : (
              <li className="flex items-start">
                <FaCheckCircle className="h-5 w-5 text-success-500 mr-2 mt-0.5" />
                <span className="text-gray-200">No suspicious elements detected</span>
              </li>
            )}
          </ul>
        </div>

        {/* Brand Impersonation */}
        {detailedAnalysis.brandImpersonation && (
          <div className="mb-6">
            <h3 className="text-lg font-medium text-white font-cyber mb-3 flex items-center">
              <FaExclamationTriangle className="mr-2 text-cyber-warning" /> Brand Impersonation
            </h3>
            <div className="bg-cyber-darker p-4 rounded border border-gray-700 shadow-cyber-glow">
              <p className="text-gray-200">{detailedAnalysis.brandImpersonation}</p>
            </div>
          </div>
        )}

        {/* URL Characteristics */}
        <div className="mb-6">
          <h3 className="text-lg font-medium text-white font-cyber mb-3 flex items-center">
            <FaLink className="mr-2 text-cyber-accent" /> URL Characteristics
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 flex items-center shadow-cyber-glow">
              <div className={features.usesHttps ? "text-success-500" : "text-danger-500"}>
                {features.usesHttps ? <FaLock className="h-5 w-5 mr-2" /> : <FaUnlock className="h-5 w-5 mr-2" />}
              </div>
              <div>
                <p className="text-white">
                  {features.usesHttps ? "Uses HTTPS" : "Uses HTTP (Insecure)"}
                </p>
              </div>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 flex items-center shadow-cyber-glow">
              <div className={features.containsHyphens ? "text-cyber-warning" : "text-success-500"}>
                <FaLink className="h-5 w-5 mr-2" />
              </div>
              <div>
                <p className="text-white">
                  {features.containsHyphens ? "Contains hyphens" : "No hyphens"}
                </p>
              </div>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 flex items-center shadow-cyber-glow">
              <div className={features.containsNumbers ? "text-cyber-warning" : "text-success-500"}>
                <FaLink className="h-5 w-5 mr-2" />
              </div>
              <div>
                <p className="text-white">
                  {features.containsNumbers ? "Contains numbers" : "No numbers"}
                </p>
              </div>
            </div>
            <div className="bg-cyber-darker p-3 rounded border border-gray-700 flex items-center shadow-cyber-glow">
              <div className={features.suspiciousTld ? "text-danger-500" : "text-success-500"}>
                <FaGlobe className="h-5 w-5 mr-2" />
              </div>
              <div>
                <p className="text-white">
                  {features.suspiciousTld ? `Unusual TLD (.${features.tld})` : `Common TLD (.${features.tld})`}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Technical Details */}
        <div className="mb-6">
          <h3 className="text-lg font-medium text-white font-cyber mb-3 flex items-center">
            <FaShieldAlt className="mr-2 text-cyber-accent" /> Technical Details
          </h3>
          <div className="bg-cyber-darker p-4 rounded border border-gray-700 shadow-cyber-glow">
            <ul className="space-y-2">
              {detailedAnalysis?.technicalDetails?.map((detail, index) => (
                <li key={index} className="text-gray-300 text-sm">• {detail}</li>
              )) || <li className="text-gray-300 text-sm">No technical details available</li>}
            </ul>
          </div>
        </div>

        {/* Recommendation */}
        <div className={`p-4 rounded-md ${isPhishing ? 'bg-danger-900/30 border border-danger-500/50' : 'bg-success-900/30 border border-success-500/50'} shadow-cyber-glow`}>
          <h3 className={`text-lg font-medium mb-2 font-cyber ${isPhishing ? 'text-danger-400' : 'text-success-400'} flex items-center`}>
            {isPhishing ? <FaExclamationTriangle className="mr-2" /> : <FaShieldAlt className="mr-2" />}
            Recommendation
          </h3>
          <p className={`${isPhishing ? 'text-danger-300' : 'text-success-300'}`}>
            {isPhishing
              ? "Do not visit this URL or enter any personal information. It appears to be a phishing site designed to steal sensitive information."
              : "This URL appears to be legitimate. However, always be cautious when entering sensitive information online."}
          </p>
        </div>
      </div>
    </div>
  );
};

export default PhishingAnalysisReport;
