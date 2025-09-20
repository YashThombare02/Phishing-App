import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add the parent directory to the path to import the app module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app import PhishingDetector

class TestHomographDetection(unittest.TestCase):
    def setUp(self):
        self.detector = PhishingDetector()
    
    def test_character_skeletonization(self):
        """Test that character skeletonization works correctly"""
        # Test individual character mapping
        self.assertEqual(self.detector._get_character_skeleton('0'), 'o')  # Digit 0 to letter o
        self.assertEqual(self.detector._get_character_skeleton('O'), 'o')  # Capital O to lowercase o
        self.assertEqual(self.detector._get_character_skeleton('о'), 'o')  # Cyrillic 'о' to Latin o
        self.assertEqual(self.detector._get_character_skeleton('1'), 'l')  # Digit 1 to letter l
        self.assertEqual(self.detector._get_character_skeleton('I'), 'l')  # Capital I to lowercase l
        
        # Test domain skeletonization
        self.assertEqual(self.detector._skeletonize_domain('g00gle'), 'google')
        self.assertEqual(self.detector._skeletonize_domain('faceb00k'), 'facebook')
        self.assertEqual(self.detector._skeletonize_domain('rnicrosoft'), 'microsoft')  # 'rn' to 'm'
        self.assertEqual(self.detector._skeletonize_domain('vvww.apple'), 'www.apple')  # 'vv' to 'w'
        self.assertEqual(self.detector._skeletonize_domain('payрal'), 'paypal')  # Cyrillic 'р' to Latin 'p'
    
    def test_homograph_detection_with_skeletonization(self):
        """Test that homograph detection works with character skeletonization"""
        # Mock the COMMON_PHISHING_TARGETS dictionary
        test_targets = {
            'google': ['google.com'],
            'paypal': ['paypal.com'],
            'microsoft': ['microsoft.com'],
            'apple': ['apple.com']
        }
        
        with patch.object(self.detector, 'COMMON_PHISHING_TARGETS', test_targets):
            # Test exact homograph attacks using character substitutions
            result = self.detector.check_homograph_attack('https://g00gle.com')
            self.assertTrue(result['result'])
            self.assertGreaterEqual(result['severity_rating'], 8)
            self.assertEqual(result['target_brands'], ['google'])
            
            # Test multi-character substitution
            result = self.detector.check_homograph_attack('https://rnicrosoft.com')
            self.assertTrue(result['result'])
            self.assertGreaterEqual(result['severity_rating'], 7)
            self.assertEqual(result['target_brands'], ['microsoft'])
            
            # Test Cyrillic character substitution
            result = self.detector.check_homograph_attack('https://рaypal.com')  # Cyrillic 'р'
            self.assertTrue(result['result'])
            self.assertGreaterEqual(result['severity_rating'], 7)
            self.assertEqual(result['target_brands'], ['paypal'])
            
            # Test domain with no homograph attack
            result = self.detector.check_homograph_attack('https://example.com')
            self.assertFalse(result['result'])
            self.assertEqual(result['severity_rating'], 0)
    
    def test_unicode_normalization_detection(self):
        """Test that Unicode normalization changes are detected"""
        # This would require actual Unicode characters that normalize differently
        # For testing purposes, we'll mock the unicodedata.normalize function
        with patch('unicodedata.normalize') as mock_normalize:
            # Simulate a case where normalization changes the domain
            mock_normalize.return_value = 'google'
            
            # Mock the COMMON_PHISHING_TARGETS dictionary
            test_targets = {'google': ['google.com']}
            
            with patch.object(self.detector, 'COMMON_PHISHING_TARGETS', test_targets):
                result = self.detector.check_homograph_attack('https://gοogle.com')  # Using a fake domain
                
                # Ensure the mock was called
                mock_normalize.assert_called()
                
                # The result should indicate a homograph attack with increased severity
                self.assertTrue(result['result'])
                self.assertGreaterEqual(result['severity_rating'], 7)  # Should be high due to Unicode tricks

if __name__ == '__main__':
    unittest.main()