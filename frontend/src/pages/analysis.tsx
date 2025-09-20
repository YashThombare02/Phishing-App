import { useEffect } from 'react';
import { useRouter } from 'next/router';

const AnalysisRedirectPage = () => {
  const router = useRouter();
  
  useEffect(() => {
    // If there's a URL parameter, redirect to the home page with that URL
    if (router.query.url) {
      router.replace(`/?url=${encodeURIComponent(router.query.url as string)}`);
    } else {
      // Otherwise, just redirect to the home page
      router.replace('/');
    }
  }, [router.query.url, router.isReady]);

  // Return null since this page will redirect
  return null;
};

export default AnalysisRedirectPage;
