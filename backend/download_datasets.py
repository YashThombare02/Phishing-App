import os
import argparse
import requests
import json
import pandas as pd
import zipfile
import io
from datetime import datetime
import sys
import time

# Configuration
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# PhishTank API URL (no key required for JSON download)
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"

# Kaggle datasets info
KAGGLE_DATASETS = [
    {
        "name": "phishing-site-urls",
        "file": "phishing_site_urls.csv",
        "description": "Dataset containing phishing and legitimate URLs"
    }
]

# UCI dataset URL
UCI_DATASET_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"

def download_phishtank():
    """Download the latest PhishTank database"""
    print("Downloading PhishTank database...")
    
    try:
        # Check if API key is provided (for better rate limits)
        api_key = os.environ.get('PHISHTANK_API_KEY', '')
        
        if api_key:
            phishtank_url = f"https://data.phishtank.com/data/{api_key}/online-valid.json"
            print("Using PhishTank API key for download")
        else:
            phishtank_url = PHISHTANK_URL
            print("No API key provided, using public download (limited)")
        
        # Download the database
        response = requests.get(phishtank_url, timeout=60)
        
        if response.status_code == 200:
            # Save the database
            output_file = os.path.join(DATA_DIR, 'phishtank_database.json')
            with open(output_file, 'wb') as f:
                f.write(response.content)
            
            # Parse to get some stats
            phishtank_data = response.json()
            print(f"Downloaded {len(phishtank_data)} phishing URLs from PhishTank")
            print(f"Database saved to {output_file}")
            
            # Create a CSV with just the URLs for easy processing
            urls = [entry['url'] for entry in phishtank_data]
            urls_df = pd.DataFrame({'url': urls, 'is_phishing': 1})
            
            csv_output = os.path.join(DATA_DIR, 'phishtank_urls.csv')
            urls_df.to_csv(csv_output, index=False)
            print(f"Extracted URLs saved to {csv_output}")
            
            return True
        else:
            print(f"Error downloading PhishTank database: {response.status_code} - {response.text}")
            return False
    
    except Exception as e:
        print(f"Exception downloading PhishTank database: {str(e)}")
        return False

def download_uci_dataset():
    """Download the UCI Phishing Websites dataset"""
    print("Downloading UCI Phishing Websites dataset...")
    
    try:
        # Download the dataset
        response = requests.get(UCI_DATASET_URL, timeout=60)
        
        if response.status_code == 200:
            # Save the original ARFF file
            arff_output = os.path.join(DATA_DIR, 'uci_dataset.arff')
            with open(arff_output, 'wb') as f:
                f.write(response.content)
            
            print(f"Downloaded UCI dataset to {arff_output}")
            
            # Convert ARFF to CSV (basic parsing)
            try:
                # Read the ARFF file
                with open(arff_output, 'r') as f:
                    lines = f.readlines()
                
                # Extract the attribute names
                attributes = []
                data_section = False
                data_lines = []
                
                for line in lines:
                    line = line.strip()
                    
                    if line.lower().startswith('@attribute'):
                        # Extract attribute name
                        attr_parts = line.split(' ')
                        if len(attr_parts) >= 2:
                            attributes.append(attr_parts[1].strip().strip("'"))
                    
                    elif line.lower().startswith('@data'):
                        data_section = True
                        continue
                    
                    if data_section and line and not line.startswith('%'):
                        data_lines.append(line)
                
                # Create a DataFrame
                data = [line.split(',') for line in data_lines]
                df = pd.DataFrame(data, columns=attributes)
                
                # Save as CSV
                csv_output = os.path.join(DATA_DIR, 'uci_dataset.csv')
                df.to_csv(csv_output, index=False)
                
                print(f"Converted to CSV: {csv_output}")
                print(f"Dataset has {len(df)} samples and {len(attributes)} features")
                
                return True
            except Exception as e:
                print(f"Error converting ARFF to CSV: {str(e)}")
                print("Falling back to original ARFF file only")
                return True
        else:
            print(f"Error downloading UCI dataset: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"Exception downloading UCI dataset: {str(e)}")
        return False

def download_legitimate_urls():
    """Download a list of legitimate URLs from the Tranco list"""
    print("Downloading legitimate URLs from Tranco list...")
    
    try:
        # Tranco list URL (top 1 million sites)
        tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
        
        # Download the zip file
        response = requests.get(tranco_url, timeout=60)
        
        if response.status_code == 200:
            # Extract the CSV from the ZIP
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                csv_name = z.namelist()[0]  # Should be only one file
                with z.open(csv_name) as f:
                    df = pd.read_csv(f, header=None, names=['rank', 'domain'])
            
            # Take the top 10,000 domains (adjust as needed)
            df = df.head(10000)
            
            # Convert to URLs (add https://)
            df['url'] = 'https://' + df['domain']
            
            # Add label (0 = legitimate)
            df['is_phishing'] = 0
            
            # Select only needed columns
            urls_df = df[['url', 'is_phishing']]
            
            # Save to CSV
            output_file = os.path.join(DATA_DIR, 'legitimate_urls.csv')
            urls_df.to_csv(output_file, index=False)
            
            print(f"Downloaded {len(urls_df)} legitimate URLs")
            print(f"Saved to {output_file}")
            
            return True
        else:
            print(f"Error downloading Tranco list: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"Exception downloading legitimate URLs: {str(e)}")
        return False

def combine_datasets():
    """Combine all downloaded datasets into a single master dataset"""
    print("Combining datasets into a master dataset...")
    
    try:
        dfs = []
        
        # Check and load PhishTank URLs
        phishtank_file = os.path.join(DATA_DIR, 'phishtank_urls.csv')
        if os.path.exists(phishtank_file):
            phishtank_df = pd.read_csv(phishtank_file)
            phishtank_df['source'] = 'phishtank'
            dfs.append(phishtank_df)
            print(f"Added {len(phishtank_df)} PhishTank URLs")
        
        # Check and load legitimate URLs
        legitimate_file = os.path.join(DATA_DIR, 'legitimate_urls.csv')
        if os.path.exists(legitimate_file):
            legitimate_df = pd.read_csv(legitimate_file)
            legitimate_df['source'] = 'tranco'
            dfs.append(legitimate_df)
            print(f"Added {len(legitimate_df)} legitimate URLs")
        
        # If we have both datasets, combine them
        if dfs:
            combined_df = pd.concat(dfs, ignore_index=True)
            
            # Shuffle the combined dataset
            combined_df = combined_df.sample(frac=1).reset_index(drop=True)
            
            # Save the combined dataset
            output_file = os.path.join(DATA_DIR, 'combined_urls.csv')
            combined_df.to_csv(output_file, index=False)
            
            print(f"Created combined dataset with {len(combined_df)} URLs")
            print(f"Phishing URLs: {len(combined_df[combined_df['is_phishing'] == 1])}")
            print(f"Legitimate URLs: {len(combined_df[combined_df['is_phishing'] == 0])}")
            print(f"Saved to {output_file}")
            
            return True
        else:
            print("No datasets found to combine")
            return False
    
    except Exception as e:
        print(f"Exception combining datasets: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Download phishing detection datasets')
    parser.add_argument('--source', choices=['all', 'phishtank', 'uci', 'legitimate', 'combine'],
                        default='all', help='Which dataset source to download')
    
    args = parser.parse_args()
    
    # Create data directory if it doesn't exist
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if args.source == 'all' or args.source == 'phishtank':
        download_phishtank()
    
    if args.source == 'all' or args.source == 'uci':
        download_uci_dataset()
    
    if args.source == 'all' or args.source == 'legitimate':
        download_legitimate_urls()
    
    if args.source == 'all' or args.source == 'combine':
        combine_datasets()
    
    print("Dataset download complete!")

if __name__ == "__main__":
    main()
