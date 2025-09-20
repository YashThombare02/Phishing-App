import React from 'react';
import { FaShieldAlt, FaGithub, FaTwitter, FaLinkedin, FaLock } from 'react-icons/fa';

const Footer: React.FC = () => {
  return (
    <footer className="bg-cyber-dark border-t border-cyber-accent/30 text-gray-300 py-8 shadow-cyber-glow">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="flex flex-col items-center mb-4 md:mb-0 w-full">
            <div className="flex items-center justify-center">
              <FaShieldAlt className="h-6 w-6 text-cyber-accent" />
              <span className="ml-2 text-lg font-semibold text-white font-cyber">PhishGuard</span>
              <span className="ml-2 text-sm text-gray-400">© {new Date().getFullYear()}</span>
            </div>
          </div>
          {/* <div className="flex space-x-4">
            <a 
              href="#" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-cyber-accent transition-colors"
            >
              <FaGithub className="h-5 w-5" />
            </a>
            <a 
              href="#" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-cyber-accent transition-colors"
            >
              <FaTwitter className="h-5 w-5" />
            </a>
            <a 
              href="#" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-cyber-accent transition-colors"
            >
              <FaLinkedin className="h-5 w-5" />
            </a>
            <a 
              href="#" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-cyber-accent transition-colors"
            >
              <FaLock className="h-5 w-5" />
            </a>
          </div> */}
        </div> 
        
        <div className="mt-6 border-t border-cyber-accent/10 pt-6">
          <p className="text-center text-sm text-gray-400">
            PhishGuard uses multiple verification methods including ML models, PhishTank, and Google Safe Browsing to detect phishing URLs.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
