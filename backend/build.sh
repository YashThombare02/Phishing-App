#!/bin/bash
set -e

# Upgrade pip and install basic build tools
pip install --upgrade pip setuptools wheel

# First install packages that don't require building from source
pip install flask==2.3.3 flask-cors==4.0.0 requests==2.31.0 python-dotenv==1.0.0 gunicorn==21.2.0

# Install numpy with specific build options
pip install numpy==1.23.5 --no-build-isolation

# Install remaining packages with dependencies on numpy
pip install pandas==1.5.3 scikit-learn==1.2.2 xgboost==1.7.6 scipy==1.10.1

# Install remaining packages
pip install -r requirements.txt --no-deps