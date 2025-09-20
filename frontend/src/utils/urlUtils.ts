/**
 * Cleans a URL string by removing whitespace and fixing common issues
 * 
 * @param url - The URL string to clean
 * @returns string - The cleaned URL
 */
export const cleanUrl = (url: string): string => {
  if (!url) return '';
  
  // Remove whitespace, tabs, newlines
  let cleaned = url.trim().replace(/\s+/g, '');
  
  // Fix duplicate http/https prefixes
  const protocolMatch = cleaned.match(/^(https?:\/\/)+/i);
  if (protocolMatch && protocolMatch[0] !== 'http://' && protocolMatch[0] !== 'https://') {
    cleaned = cleaned.replace(/^(https?:\/\/)+/i, '');
    cleaned = `https://${cleaned}`;
  }
  
  return cleaned;
};

/**
 * Validates if a string is a valid URL
 * 
 * @param url - The URL string to validate
 * @returns boolean - Whether the URL is valid
 */
export const isValidUrl = (url: string): boolean => {
  try {
    // Clean the URL first
    const cleanedUrl = cleanUrl(url);
    
    // Try to create a URL object
    new URL(cleanedUrl);
    
    // Additional validation - must have a hostname with at least one dot
    return cleanedUrl.includes('://') && new URL(cleanedUrl).hostname.includes('.');
  } catch (e) {
    // If it throws, the URL is not valid
    return false;
  }
};

/**
 * Formats a URL by adding https:// if missing
 * 
 * @param url - The URL string to format
 * @returns string - The formatted URL
 */
export const formatUrl = (url: string): string => {
  if (!url) return '';
  
  // Clean the URL first
  const cleanedUrl = cleanUrl(url);
  
  // Add https:// if no protocol is specified
  if (!cleanedUrl.startsWith('http://') && !cleanedUrl.startsWith('https://')) {
    return `https://${cleanedUrl}`;
  }
  
  return cleanedUrl;
};

/**
 * Extracts the domain from a URL
 * 
 * @param url - The URL to extract domain from
 * @returns string - The domain
 */
export const extractDomain = (url: string): string => {
  try {
    // Clean and format the URL first
    const formattedUrl = formatUrl(url);
    const urlObj = new URL(formattedUrl);
    return urlObj.hostname;
  } catch (e) {
    return url;
  }
};

/**
 * Shortens a URL for display
 * 
 * @param url - The URL to shorten
 * @param maxLength - Maximum length before truncating
 * @returns string - The shortened URL
 */
export const shortenUrl = (url: string, maxLength: number = 50): string => {
  if (!url) return '';
  
  // Clean and format the URL first
  const cleanedUrl = formatUrl(url);
  
  if (cleanedUrl.length <= maxLength) return cleanedUrl;
  
  // Try to preserve the domain part
  const domain = extractDomain(cleanedUrl);
  
  if (domain.length >= maxLength - 3) {
    // If domain itself is too long, truncate it
    return domain.substring(0, maxLength - 3) + '...';
  }
  
  try {
    // Calculate how much of the URL path we can show
    const urlObj = new URL(cleanedUrl);
    const pathPart = urlObj.pathname + urlObj.search + urlObj.hash;
    
    if (domain.length + pathPart.length <= maxLength) {
      return urlObj.toString();
    }
    
    // Truncate the path part
    const availableChars = maxLength - domain.length - 3; // -3 for '...'
    const truncatedPath = pathPart.substring(0, availableChars) + '...';
    
    return `${urlObj.protocol}//${domain}${truncatedPath}`;
  } catch (e) {
    // Fallback in case of errors
    return cleanedUrl.substring(0, maxLength - 3) + '...';
  }
};
