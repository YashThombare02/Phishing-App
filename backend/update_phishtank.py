import os
import json
import shutil
from datetime import datetime

# Define paths
base_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(base_dir, 'data')
enhanced_db_path = os.path.join(data_dir, 'enhanced_phishtank_database.json')
phishtank_db_path = os.path.join(data_dir, 'phishtank_database.json')

def update_phishtank_database():
    """
    Update the PhishTank database with our enhanced dataset
    """
    # Create data directory if it doesn't exist
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # Check if enhanced database exists
    if not os.path.exists(enhanced_db_path):
        print(f"Error: Enhanced database not found at {enhanced_db_path}")
        return False
    
    try:
        # Load the enhanced database
        with open(enhanced_db_path, 'r') as f:
            enhanced_data = json.load(f)
        
        # Create a backup of existing database if it exists
        if os.path.exists(phishtank_db_path):
            backup_path = f"{phishtank_db_path}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            shutil.copy2(phishtank_db_path, backup_path)
            print(f"Created backup of existing database at {backup_path}")
        
        # Save the enhanced data to the PhishTank database path
        with open(phishtank_db_path, 'w') as f:
            json.dump(enhanced_data, f, indent=2)
        
        print(f"Successfully updated PhishTank database with {len(enhanced_data)} entries")
        print("Database is now available at:", phishtank_db_path)
        return True
    
    except Exception as e:
        print(f"Error updating PhishTank database: {str(e)}")
        return False

if __name__ == "__main__":
    print("Updating PhishTank database...")
    update_phishtank_database()
