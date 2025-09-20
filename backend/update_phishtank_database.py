#!/usr/bin/env python3
"""
Script to download the PhishTank database
"""

from download_phishtank import download_phishtank_database

if __name__ == "__main__":
    print("Manually downloading PhishTank database...")
    success = download_phishtank_database()
    
    if success:
        print("✅ PhishTank database downloaded successfully!")
    else:
        print("⚠️ Failed to download PhishTank database, sample database created instead.")
    
    print("\nTo use this database with PhishGuard, restart the backend server.")
