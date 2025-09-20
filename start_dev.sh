#!/bin/bash

echo "===== PhishGuard Development Startup Script ====="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    echo "Please install Python 3.9 or higher"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js is not installed"
    echo "Please install Node.js 16 or higher"
    exit 1
fi

# Create a virtual environment for the backend if it doesn't exist
if [ ! -d "backend/venv" ]; then
    echo "Creating Python virtual environment..."
    cd backend
    python3 -m venv venv
    cd ..
fi

# Activate the virtual environment and install dependencies
echo "Activating Python virtual environment and installing dependencies..."
source backend/venv/bin/activate
cd backend
pip install -r requirements.txt

# Train models if they don't exist
if [ ! -f "models/uci_model.pkl" ]; then
    echo "Training machine learning models..."
    python train_models.py
fi

# Start the backend in a new terminal window
echo "Starting backend server..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    osascript -e 'tell app "Terminal" to do script "cd '$(pwd)' && source venv/bin/activate && python app.py"'
else
    # Linux
    gnome-terminal -- bash -c "source venv/bin/activate; python app.py; exec bash" || \
    xterm -e "source venv/bin/activate; python app.py; exec bash" || \
    x-terminal-emulator -e "source venv/bin/activate; python app.py; exec bash" || \
    echo "Could not open a new terminal window. Please start the backend manually."
fi
cd ..

# Install frontend dependencies if node_modules doesn't exist
if [ ! -d "frontend/node_modules" ]; then
    echo "Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
fi

# Start the frontend in a new terminal window
echo "Starting frontend server..."
cd frontend
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    osascript -e 'tell app "Terminal" to do script "cd '$(pwd)' && npm run dev"'
else
    # Linux
    gnome-terminal -- bash -c "npm run dev; exec bash" || \
    xterm -e "npm run dev; exec bash" || \
    x-terminal-emulator -e "npm run dev; exec bash" || \
    echo "Could not open a new terminal window. Please start the frontend manually."
fi
cd ..

echo ""
echo "PhishGuard development environment is now running!"
echo "Backend: http://localhost:5000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C in each terminal window to stop the servers when done."
