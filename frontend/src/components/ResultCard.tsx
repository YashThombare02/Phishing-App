import React from 'react';
import { FaShieldAlt, FaExclamationTriangle, FaCheck, FaInfoCircle, FaDatabase, FaRobot, FaGlobe, FaCalculator, FaFileAlt } from 'react-icons/fa';
import { DetectionResult, VerificationMethod } from '@/utils/api';
import { shortenUrl } from '@/utils/urlUtils';

interface ResultCardProps {
  result: DetectionResult;
}

// Safe accessor function to handle potentially undefined values
const safeGet = (obj: any, path: string, defaultValue: any = undefined) => {
  const keys = path.split('.');
  let current = obj;
  
  for (let i = 0; i < keys.length; i++) {
    if (current === undefined || current === null) {
      return defaultValue;
    }
    current = current[keys[i]];
  }
  
  return current === undefined ? defaultValue : current;
};

const ResultCard: React.FC<ResultCardProps> = ({ result }) => {
  if (!result) {
    return <div className="p-4 bg-gray-100 rounded-lg">No result data available</div>;
  }
  
  const url = safeGet(result, 'url', '');
  const final_verdict = safeGet(result, 'final_verdict', false);
  const confidence = safeGet(result, 'confidence', 0);
  const explanations = safeGet(result, 'explanations', []);
  
  // Additional URL structure analysis
  let domain = '';
  let hasSuspiciousHyphen = false;
  let impersonationRisk = false;
  
  try {
    const parsedUrl = new URL(url);
    domain = parsedUrl.hostname;
    const domainParts = domain.split('.');
    hasSuspiciousHyphen = domain.includes('-') && domain.split('-')[0].includes('.');
    impersonationRisk = hasSuspiciousHyphen || domain.includes('pl-');
  } catch (error) {
    console.error("Error parsing URL:", error);
  }
  
  // Format confidence as percentage
  const confidencePercent = parseFloat((confidence * 100).toFixed(2));
  
  // Determine the color scheme based on the verdict
  const cardColorClass = final_verdict 
    ? 'border-danger-500 bg-danger-50' 
    : 'border-success-500 bg-success-50';
  
  const headerColorClass = final_verdict 
    ? 'bg-danger-500 text-white' 
    : 'bg-success-500 text-white';
  
  // Helper function to safely render verification method
  const renderMethodItem = (methodKey: string, label: string) => {
    const method = safeGet(result, `verification_methods.${methodKey}`);
    
    if (!method) return null;
    
    const isRisky = safeGet(method, 'result', false);
    const description = safeGet(method, 'description', 'No information available');
    const value = safeGet(method, 'value', null);
    
    // Special handling for ML models with negative predictions
    const isNegativePrediction = description && description.includes("-1");
    
    // Skip showing the "high risk score" for negative predictions
    const showRiskScore = value !== null && methodKey === 'uci_model' && isRisky && !isNegativePrediction;
    
    return (
      <div className={`flex items-center ${isRisky ? 'py-1 px-1 bg-amber-50 rounded-md' : ''}`}>
        <span className={isRisky ? "text-danger-600 font-bold" : "text-success-600"}>
          {isRisky ? "⚠️" : "✅"}
        </span>
        <span className={`ml-2 ${isRisky ? 'text-amber-800' : ''}`}>
          {label}: {description}
          {showRiskScore && (
            <span className="font-medium text-danger-700 ml-1">
              (High risk score: {Math.abs(value * 100).toFixed(0)}%)
            </span>
          )}
        </span>
      </div>
    );
  };

  return (
    <div className={`border-2 rounded-lg overflow-hidden shadow-lg mb-6 ${cardColorClass}`}>
      {/* Header */}
      <div className={`px-4 py-3 ${headerColorClass}`}>
        <div className="flex justify-between items-center">
          <h3 className="text-lg font-semibold flex items-center">
            {final_verdict ? (
              <FaExclamationTriangle className="mr-2" />
            ) : confidence > 10 ? (
              <FaInfoCircle className="mr-2" />
            ) : (
              <FaShieldAlt className="mr-2" />
            )}
            {final_verdict 
              ? 'Phishing Detected' 
              : confidence > 10 
                ? 'Potentially Suspicious' 
                : 'URL is Safe'}
          </h3>
          <span className="text-sm font-medium bg-white bg-opacity-20 px-2 py-1 rounded-full">
            {confidencePercent.toFixed(2)}% Confidence
          </span>
        </div>
      </div>
      
      {/* URL Section */}
      <div className="px-4 py-3 bg-white">
        <p className="text-sm text-gray-500">URL Analyzed:</p>
        <p className="text-base font-medium text-gray-800 break-all">
          {url}
        </p>
      </div>

      {/* Verification Process */}
      <div className="px-4 py-3 bg-white border-t border-gray-200">
        <h4 className="text-sm font-semibold text-gray-700 mb-3">
          🔍 Verification Process
        </h4>
        
        {/* Step 1: URL Preprocessing */}
        <div className="mb-3 border-l-4 border-primary-300 pl-3">
          <div className="flex items-start">
            <div className="bg-primary-100 rounded-full p-2 mr-3">
              <FaFileAlt className="text-primary-600" />
            </div>
            <div>
              <h5 className="text-sm font-medium text-gray-700">1. URL Preprocessing</h5>
              <p className="text-xs text-gray-600 mt-1">
                Normalized and parsed URL components for analysis
              </p>
            </div>
          </div>
        </div>
        
        {/* Step 2: External Database Checks */}
        <div className="mb-3 border-l-4 border-primary-300 pl-3">
          <div className="flex items-start">
            <div className="bg-primary-100 rounded-full p-2 mr-3">
              <FaDatabase className="text-primary-600" />
            </div>
            <div className="flex-grow">
              <h5 className="text-sm font-medium text-gray-700">2. External Database Checks</h5>
              <div className="text-xs mt-1 space-y-1">
                {renderMethodItem('phishtank', 'PhishTank')}
                {renderMethodItem('google_safe_browsing', 'Google Safe Browsing')}
              </div>
            </div>
          </div>
        </div>
        
        {/* Step 3: Machine Learning Models */}
        <div className="mb-3 border-l-4 border-primary-300 pl-3">
          <div className="flex items-start">
            <div className="bg-primary-100 rounded-full p-2 mr-3">
              <FaRobot className="text-primary-600" />
            </div>
            <div className="flex-grow">
              <h5 className="text-sm font-medium text-gray-700">3. Machine Learning Analysis</h5>
              <div className="text-xs mt-1 space-y-1">
                {renderMethodItem('uci_model', 'Random Forest (UCI)')}
                {renderMethodItem('advanced_model', 'XGBoost (Advanced)')}
              </div>
            </div>
          </div>
        </div>
        
        {/* Step 4: Domain Analysis */}
        <div className="mb-3 border-l-4 border-primary-300 pl-3">
          <div className="flex items-start">
            <div className="bg-primary-100 rounded-full p-2 mr-3">
              <FaGlobe className="text-primary-600" />
            </div>
            <div>
              <h5 className="text-sm font-medium text-gray-700">4. Domain & Heuristic Analysis</h5>
              <div className="text-xs mt-1">
                {renderMethodItem('domain_age_days', 'Domain Age')}
              </div>
            </div>
          </div>
        </div>
        
        {/* Step 5: Final Score */}
        <div className="mb-3 border-l-4 border-primary-300 pl-3">
          <div className="flex items-start">
            <div className="bg-primary-100 rounded-full p-2 mr-3">
              <FaCalculator className="text-primary-600" />
            </div>
            <div>
              <h5 className="text-sm font-medium text-gray-700">5. Final Weighted Score</h5>
              <div className="mt-1">
                <div className="h-4 w-full bg-gray-200 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${final_verdict ? 'bg-danger-500' : 'bg-success-500'}`}
                    style={{ width: `${Math.min(confidencePercent, 100)}%` }}
                  ></div>
                </div>
                <p className="text-xs text-gray-600 mt-1">
                  Score: {confidencePercent.toFixed(2)}% {final_verdict ? 'suspicious' : 'safe'} 
                  (Threshold: 25%)
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* New Risk Assessment Section */}
      <div className="px-4 py-3 bg-white border-t border-gray-200">
        <h4 className="text-sm font-semibold text-gray-700 mb-3 flex items-center">
          <FaExclamationTriangle className="mr-2 text-amber-500" />
          Risk Assessment
        </h4>
        
        {/* Check for brand impersonation */}
        {impersonationRisk && (
          <div className="mb-2 p-2 bg-amber-50 border border-amber-200 rounded-md">
            <p className="text-xs text-amber-800 font-medium">High Risk: Brand Impersonation Detected</p>
            <p className="text-xs text-amber-700">
              This URL appears to be impersonating a legitimate website using a deceptive domain structure.
              The domain "{domain}" uses a hyphen after what looks like a legitimate domain name, which is 
              a common phishing tactic.
            </p>
          </div>
        )}
        
        {/* Check for very new domains */}
        {safeGet(result, 'verification_methods.domain_age_days.result', false) && (
          <div className="mb-2 p-2 bg-amber-50 border border-amber-200 rounded-md">
            <p className="text-xs text-amber-800 font-medium">New Domain Warning</p>
            <p className="text-xs text-amber-700">
              This domain is very new ({safeGet(result, 'verification_methods.domain_age_days.description', '')}).
              Newly created domains are commonly used in phishing attacks.
            </p>
          </div>
        )}
        
        {/* Check for ML model conflicts */}
        {(safeGet(result, 'verification_methods.uci_model.result', false) !== 
         safeGet(result, 'verification_methods.advanced_model.result', false)) && 
         safeGet(result, 'verification_methods.uci_model.value', 0) > 0 && (
          <div className="mb-2 p-2 bg-amber-50 border border-amber-200 rounded-md">
            <p className="text-xs text-amber-800 font-medium">Conflicting Analysis Results</p>
            <p className="text-xs text-amber-700">
              Our machine learning models produced different results. This could indicate a sophisticated phishing attempt
              or a borderline case. We recommend caution.
            </p>
          </div>
        )}
        
        {/* Final recommendation */}
        <div className={`mt-3 p-2 rounded-md ${final_verdict ? 'bg-danger-100 border border-danger-200' : 'bg-gray-100 border border-gray-200'}`}>
          <p className={`text-sm font-medium ${final_verdict ? 'text-danger-800' : 'text-gray-800'}`}>Recommendation:</p>
          <p className="text-xs mt-1">
            {final_verdict
              ? "This URL has been classified as phishing. Do not proceed or enter any personal information."
              : confidence > 10
                ? "While this URL was not classified as phishing, it has some suspicious characteristics. Proceed with caution."
                : "This URL appears to be safe based on our analysis."
            }
          </p>
        </div>
      </div>
      
      {/* Explanations */}
      {Array.isArray(explanations) && explanations.length > 0 && (
        <div className="px-4 py-3 bg-white border-t border-gray-200">
          <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
            <FaInfoCircle className="mr-2 text-primary-500" />
            {final_verdict 
              ? "Why we flagged this as suspicious" 
              : "Risk factors detected (but below threshold)"}
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
            {explanations.map((explanation, index) => {
              // Check if explanation is system-generated and modify display accordingly
              const isSystemGenerated = explanation.includes("Based on multiple factors") || 
                                        explanation.includes("Our analysis indicates");
              
              return (
                <li key={index} className={isSystemGenerated ? "text-gray-600" : "text-amber-700"}>
                  {explanation}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ResultCard;
