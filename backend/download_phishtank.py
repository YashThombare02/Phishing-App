import os
import json
import requests
import time
import zipfile
import io

def download_phishtank_database():
    """
    Downloads the PhishTank database of verified phishing URLs
    """
    print("Downloading PhishTank database...")
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # PhishTank database URL
    database_url = "https://data.phishtank.com/data/online-valid.json.zip"
    
    try:
        # Download the database
        response = requests.get(database_url, timeout=30)
        if response.status_code == 200:
            # Extract the database from the zip file
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                # Get the first file in the zip
                json_filename = z.namelist()[0]
                
                # Extract the file
                with z.open(json_filename) as f:
                    phishtank_data = json.loads(f.read().decode('utf-8'))
                
                # Save the database to a file
                output_file = os.path.join(data_dir, 'phishtank_database.json')
                with open(output_file, 'w') as f:
                    json.dump(phishtank_data, f)
                
                print(f"PhishTank database downloaded successfully ({len(phishtank_data)} entries)")
                return True
        else:
            print(f"Failed to download PhishTank database: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"Error downloading PhishTank database: {str(e)}")
        
        # Create a sample database with some known phishing URLs if download fails
        create_sample_phishtank_database()
        return False

def create_sample_phishtank_database():
    """
    Creates a sample PhishTank database with some known phishing URLs
    """
    print("Creating sample PhishTank database...")
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Sample phishing URLs (these are just examples and may not be active phishing sites)
    sample_data = [
        {
            "phish_id": "7829173",
            "url": "http://paypal-secure-login.com",
            "submission_time": "2023-09-20T10:15:20+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T11:30:45+00:00",
            "target": "PayPal"
        },
        {
            "phish_id": "7829174",
            "url": "https://google-login-verification.com",
            "submission_time": "2023-09-20T09:12:18+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T10:45:12+00:00",
            "target": "Google"
        },
        {
            "phish_id": "7829175",
            "url": "http://microsoft-365-verify-account.com",
            "submission_time": "2023-09-20T14:08:55+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T15:30:22+00:00",
            "target": "Microsoft"
        },
        {
            "phish_id": "7829176",
            "url": "https://apple-id-verification-service.com",
            "submission_time": "2023-09-20T08:33:47+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T09:15:33+00:00",
            "target": "Apple"
        },
        {
            "phish_id": "7829177",
            "url": "http://amazon-account-verify.com",
            "submission_time": "2023-09-20T11:42:19+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T12:55:10+00:00",
            "target": "Amazon"
        }
    ]
    
    # Add more URLs from a list of common phishing patterns
    phishing_domains = [
        "secure-bank-login.com",
        "account-verification-center.com",
        "banking-secure-signin.net",
        "verify-your-account-now.com",
        "online-banking-secure.com",
        "confirm-your-identity.net",
        "security-alert-update.com",
        "facebook-security-check.com",
        "instagram-verify-account.com",
        "netflix-subscription-update.com",
        "twitter-account-verify.com",
        "linkedin-profile-check.com",
        "dropbox-share-document.com",
        "gmail-security-alert.com",
        "chase-bank-secure.com",
        "wellsfargo-verify.com",
        "citibank-online.com",
        "bankofamerica-secure.com",
        "paypal-resolution-center.com",
        "ebay-purchase-confirmation.com"
    ]
    
    # Add the additional domains to the sample data
    for i, domain in enumerate(phishing_domains):
        sample_data.append({
            "phish_id": f"7829{178+i}",
            "url": f"http://{domain}",
            "submission_time": "2023-09-20T16:00:00+00:00",
            "verified": "yes",
            "verification_time": "2023-09-20T17:00:00+00:00",
            "target": "Various"
        })
    
    # Save the sample database to a file
    output_file = os.path.join(data_dir, 'phishtank_database.json')
    with open(output_file, 'w') as f:
        json.dump(sample_data, f)
    
    print(f"Sample PhishTank database created ({len(sample_data)} entries)")

if __name__ == "__main__":
    download_phishtank_database()
