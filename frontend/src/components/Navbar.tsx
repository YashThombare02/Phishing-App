import React from 'react';
import { FaShieldAlt, FaInfoCircle, FaDatabase, FaGithub, FaExclamationTriangle } from 'react-icons/fa';
import Link from 'next/link';

interface NavbarProps {
  activePage: 'home' | 'about' | 'stats' | 'batch' | 'report' | 'analysis';
}

const Navbar: React.FC<NavbarProps> = ({ activePage }) => {
  const navItems = [
    { name: 'Home', path: '/', icon: <FaShieldAlt className="mr-2" />, active: activePage === 'home' },
    { name: 'About', path: '/about', icon: <FaInfoCircle className="mr-2" />, active: activePage === 'about' },
    { name: 'Stats', path: '/stats', icon: <FaDatabase className="mr-2" />, active: activePage === 'stats' },
    { name: 'Batch Analysis', path: '/batch', icon: <FaDatabase className="mr-2" />, active: activePage === 'batch' },
    { name: 'Report Phishing', path: '/report', icon: <FaExclamationTriangle className="mr-2" />, active: activePage === 'report' }
  ];

  return (
    <nav className="bg-cyber-gradient shadow-cyber-glow border-b border-cyber-accent/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <div className="flex-shrink-0 flex items-center">
              <Link href="/" className="flex items-center">
                <FaShieldAlt className="h-8 w-8 text-cyber-accent animate-pulse-glow" />
                <span className="ml-2 text-xl font-bold text-white font-cyber">PhishGuard</span>
              </Link>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  href={item.path}
                  className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                    item.active
                      ? 'border-cyber-accent text-white'
                      : 'border-transparent text-gray-300 hover:text-white hover:border-cyber-accent/50'
                  }`}
                >
                  {item.icon}
                  {item.name}
                </Link>
              ))}
            </div>
          </div>
          <div className="hidden sm:ml-6 sm:flex sm:items-center">
            <a
              href="https://github.com/yourusername/phishing-detector"
              target="_blank"
              rel="noopener noreferrer"
              className="p-1 rounded-full text-gray-300 hover:text-cyber-accent focus:outline-none"
            >
              <FaGithub className="h-6 w-6" />
            </a>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      <div className="sm:hidden">
        <div className="pt-2 pb-3 space-y-1">
          {navItems.map((item) => (
            <Link
              key={item.name}
              href={item.path}
              className={`block pl-3 pr-4 py-2 border-l-4 text-base font-medium ${
                item.active
                  ? 'bg-cyber-dark border-cyber-accent text-cyber-accent'
                  : 'border-transparent text-gray-300 hover:bg-cyber-darker hover:border-cyber-accent/50 hover:text-white'
              }`}
            >
              <div className="flex items-center">
                {item.icon}
                {item.name}
              </div>
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
