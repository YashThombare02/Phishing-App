import React, { ReactNode } from 'react';
import Navbar from './Navbar';
import Footer from './Footer';

interface LayoutProps {
  children: ReactNode;
  activePage: 'home' | 'about' | 'stats' | 'batch' | 'report' | 'analysis';
}

const Layout: React.FC<LayoutProps> = ({ children, activePage }) => {
  return (
    <div className="flex flex-col min-h-screen bg-cyber-darker text-gray-100">
      <Navbar activePage={activePage} />
      <main className="flex-grow">
        {children}
      </main>
      <Footer />
    </div>
  );
};

export default Layout;
