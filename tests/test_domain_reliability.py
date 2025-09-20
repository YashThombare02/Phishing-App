import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import hashlib

# Add the parent directory to the path to import the app module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import PhishingDetector

class TestDomainReliability(unittest.TestCase):
    def setUp(self):
        self.detector = PhishingDetector()
    
    @patch('dns.resolver.resolve')
    @patch('socket.gethostbyname_ex')
    def test_domain_reliability_good_domain(self, mock_gethostbyname, mock_dns_resolve):
        # Mock socket.gethostbyname_ex to simulate successful DNS resolution
        mock_gethostbyname.return_value = ('example.com', [], ['93.184.216.34'])
        
        # Create a mock for MX records
        mx_mock = MagicMock()
        mx_items = [MagicMock() for _ in range(2)]
        mx_mock.__iter__.return_value = mx_items
        
        # Create a mock for A records
        a_mock = MagicMock()
        a_items = [MagicMock() for _ in range(2)]
        a_mock.__iter__.return_value = a_items
        a_mock.__len__.return_value = 2
        # Set the first A record to return a string value when converted to string
        a_items[0].__str__.return_value = '93.184.216.34'
        
        # Create a mock for TXT records
        txt_mock = MagicMock()
        txt_items = [MagicMock()]
        txt_mock.__iter__.return_value = txt_items
        
        # Create a mock for NS records
        ns_mock = MagicMock()
        ns_items = [MagicMock() for _ in range(2)]
        ns_mock.__iter__.return_value = ns_items
        ns_mock.__len__.return_value = 2
        ns_mock.ttl = 3600  # Good TTL value
        
        # Set up the mock to return different values for different record types
        def mock_resolve_side_effect(domain, record_type):
            if record_type == 'MX':
                return mx_mock
            elif record_type == 'A':
                return a_mock
            elif record_type == 'TXT':
                return txt_mock
            elif record_type == 'NS':
                return ns_mock
            raise Exception(f"Unexpected record type: {record_type}")
        
        mock_dns_resolve.side_effect = mock_resolve_side_effect
        
        # Test the function
        result = self.detector.check_domain_creation_date_reliability('https://example.com')
        
        # Assertions
        self.assertFalse(result['result'])  # Should not be suspicious
        self.assertGreaterEqual(result['reliability_rating'], 7)  # Should have high reliability
        self.assertIn('Has valid mail exchange (MX) records', result['reliability_factors'])
        self.assertIn('Multiple IP addresses', result['reliability_factors'])
        self.assertIn('Has TXT records for domain verification', result['reliability_factors'])
        self.assertIn('Has 2 nameservers (good redundancy)', result['reliability_factors'])
    
    @patch('dns.resolver.resolve')
    @patch('socket.gethostbyname_ex')
    def test_domain_reliability_suspicious_domain(self, mock_gethostbyname, mock_dns_resolve):
        # Mock socket.gethostbyname_ex to simulate successful DNS resolution
        mock_gethostbyname.return_value = ('suspicious-example.com', [], ['192.0.2.1'])
        
        # Create a mock for A records only (no MX, TXT or NS records)
        a_mock = MagicMock()
        a_items = [MagicMock()]
        a_mock.__iter__.return_value = a_items
        a_mock.__len__.return_value = 1
        # Set the A record to return a string value when converted to string
        a_items[0].__str__.return_value = '192.0.2.1'
        
        # Set up the mock to return A records but raise exceptions for other types
        def mock_resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return a_mock
            raise Exception(f"No {record_type} records found")
        
        mock_dns_resolve.side_effect = mock_resolve_side_effect
        
        # Test the function
        result = self.detector.check_domain_creation_date_reliability('https://suspicious-example.com')
        
        # Assertions
        self.assertTrue(result['result'])  # Should be suspicious
        self.assertLessEqual(result['reliability_rating'], 4)  # Should have low reliability
        self.assertIn('No mail exchange records', result['reliability_factors'])
        self.assertNotIn('Has TXT records for domain verification', result['reliability_factors'])
        self.assertIn('No NS records found', result['reliability_factors'])
    
    @patch('socket.gethostbyname_ex')
    def test_domain_reliability_no_dns(self, mock_gethostbyname):
        # Mock socket.gethostbyname_ex to simulate failed DNS resolution
        mock_gethostbyname.side_effect = Exception("No such domain")
        
        # Test the function
        result = self.detector.check_domain_creation_date_reliability('https://nonexistent-domain.com')
        
        # Assertions
        self.assertTrue(result['result'])  # Should be suspicious
        self.assertEqual(result['reliability_rating'], 0)  # Should have zero reliability
        self.assertEqual(result['reliability_description'], "No DNS Records: Highly suspicious")
    
    @patch('dns.resolver.resolve')
    @patch('socket.gethostbyname_ex')
    def test_domain_reliability_fast_flux(self, mock_gethostbyname, mock_dns_resolve):
        # Mock socket.gethostbyname_ex to simulate successful DNS resolution
        mock_gethostbyname.return_value = ('fast-flux-example.com', [], ['192.0.2.1'])
        
        # Create a mock for A records
        a_mock = MagicMock()
        a_items = [MagicMock()]
        a_mock.__iter__.return_value = a_items
        a_mock.__len__.return_value = 1
        a_items[0].__str__.return_value = '192.0.2.1'
        
        # Create a mock for NS records with very short TTL
        ns_mock = MagicMock()
        ns_items = [MagicMock() for _ in range(2)]
        ns_mock.__iter__.return_value = ns_items
        ns_mock.__len__.return_value = 2
        ns_mock.ttl = 60  # Very short TTL (1 minute)
        
        # Set up the mock to return different values for different record types
        def mock_resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return a_mock
            elif record_type == 'NS':
                return ns_mock
            raise Exception(f"No {record_type} records found")
        
        mock_dns_resolve.side_effect = mock_resolve_side_effect
        
        # Test the function
        result = self.detector.check_domain_creation_date_reliability('https://fast-flux-example.com')
        
        # Assertions
        self.assertIn('Very short TTL (60s) - potential fast-flux indicator', result['reliability_factors'])
        self.assertLessEqual(result['reliability_rating'], 5)  # Should have reduced reliability due to short TTL

if __name__ == '__main__':
    unittest.main()