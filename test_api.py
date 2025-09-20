import requests
import json
import sys

def test_api_endpoint(endpoint, payload=None, method="GET"):
    """Test an API endpoint and return the response"""
    url = f"http://localhost:5000/api/{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url)
        elif method.upper() == "POST":
            response = requests.post(url, json=payload)
        else:
            print(f"Unsupported method: {method}")
            return None
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error calling {url}: {e}")
        return None

def main():
    # Test the stats endpoint (GET)
    print("\n=== Testing /api/stats ===")
    stats = test_api_endpoint("stats")
    if stats:
        print(json.dumps(stats, indent=2))
    
    # Test the verification_methods endpoint (GET)
    print("\n=== Testing /api/verification_methods ===")
    methods = test_api_endpoint("verification_methods")
    if methods:
        print(json.dumps(methods, indent=2))
    
    # Test the detect endpoint with a legitimate URL (POST)
    print("\n=== Testing /api/detect with legitimate URL ===")
    legitimate_result = test_api_endpoint("detect", {"url": "https://example.com"}, "POST")
    if legitimate_result:
        print(json.dumps(legitimate_result, indent=2))
    
    # Test the detect endpoint with a suspicious URL (POST)
    print("\n=== Testing /api/detect with suspicious URL ===")
    phishing_result = test_api_endpoint("detect", {"url": "https://btinternetcomxxchn-dk96.glide.page/dl/2432"}, "POST")
    if phishing_result:
        print(json.dumps(phishing_result, indent=2))
    
    # Test the statistics endpoint (GET)
    print("\n=== Testing /api/statistics ===")
    statistics = test_api_endpoint("statistics")
    if statistics:
        print(json.dumps(statistics, indent=2))

if __name__ == "__main__":
    main()