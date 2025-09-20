# Deployment Guide: PhishGuard

This document provides instructions for deploying the PhishGuard phishing detection system in a production environment.

## Prerequisites

- Python 3.9+ for the backend
- Node.js 16+ for the frontend
- Git for version control
- Basic understanding of web hosting and server management

## Deployment Options

PhishGuard can be deployed using several different methods:

1. **Traditional Server Deployment**: Hosting the backend and frontend on separate servers
2. **Container-Based Deployment**: Using Docker and Docker Compose
3. **Serverless Deployment**: Using services like Vercel for frontend and AWS Lambda for backend

## Option 1: Traditional Server Deployment

### Backend Deployment

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd phishingURL
   ```

2. Set up a Python virtual environment:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configure the production settings:
   - Set up environment variables for API keys:
     ```bash
     export PHISHTANK_API_KEY="your_phishtank_api_key"
     export GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key"
     ```

4. Train the machine learning models:
   ```bash
   python train_models.py
   ```

5. Set up a production WSGI server (Gunicorn):
   ```bash
   gunicorn --workers=4 --bind=0.0.0.0:5000 app:app
   ```

6. Set up Nginx as a reverse proxy:
   ```
   server {
       listen 80;
       server_name your-domain.com;

       location /api {
           proxy_pass http://localhost:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }

       location / {
           proxy_pass http://localhost:3000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

7. Set up SSL with Let's Encrypt:
   ```bash
   sudo certbot --nginx -d your-domain.com
   ```

### Frontend Deployment

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Update the API URL in `src/utils/api.ts`:
   ```typescript
   const API_BASE_URL = '/api';  // This works with the Nginx config above
   ```

4. Build the frontend:
   ```bash
   npm run build
   ```

5. Set up a process manager (PM2) to run the Next.js server:
   ```bash
   npm install -g pm2
   pm2 start npm --name "phishguard-frontend" -- start
   ```

## Option 2: Docker Deployment

1. Create a `Dockerfile` for the backend:
   ```dockerfile
   FROM python:3.9-slim

   WORKDIR /app

   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt

   COPY . .

   RUN python train_models.py

   EXPOSE 5000

   CMD ["gunicorn", "--workers=4", "--bind=0.0.0.0:5000", "app:app"]
   ```

2. Create a `Dockerfile` for the frontend:
   ```dockerfile
   FROM node:16-alpine

   WORKDIR /app

   COPY package*.json ./
   RUN npm install

   COPY . .

   RUN npm run build

   EXPOSE 3000

   CMD ["npm", "start"]
   ```

3. Create a `docker-compose.yml` file:
   ```yaml
   version: '3'

   services:
     backend:
       build: ./backend
       ports:
         - "5000:5000"
       environment:
         - PHISHTANK_API_KEY=${PHISHTANK_API_KEY}
         - GOOGLE_SAFE_BROWSING_API_KEY=${GOOGLE_SAFE_BROWSING_API_KEY}
       volumes:
         - ./backend/data:/app/data
       restart: always

     frontend:
       build: ./frontend
       ports:
         - "3000:3000"
       depends_on:
         - backend
       restart: always

     nginx:
       image: nginx:latest
       ports:
         - "80:80"
         - "443:443"
       volumes:
         - ./nginx/conf:/etc/nginx/conf.d
         - ./nginx/certbot/conf:/etc/letsencrypt
         - ./nginx/certbot/www:/var/www/certbot
       depends_on:
         - backend
         - frontend
       restart: always
   ```

4. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Option 3: Serverless Deployment

### Backend Deployment (AWS Lambda)

1. Create a `serverless.yml` configuration:
   ```yaml
   service: phishguard-api

   provider:
     name: aws
     runtime: python3.9
     region: us-east-1
     environment:
       PHISHTANK_API_KEY: ${env:PHISHTANK_API_KEY}
       GOOGLE_SAFE_BROWSING_API_KEY: ${env:GOOGLE_SAFE_BROWSING_API_KEY}

   functions:
     app:
       handler: serverless_handler.handler
       events:
         - http:
             path: /{proxy+}
             method: any
   ```

2. Create a `serverless_handler.py` file:
   ```python
   import app
   from serverless_wsgi import handle_request

   def handler(event, context):
       return handle_request(app.app, event, context)
   ```

3. Deploy with Serverless Framework:
   ```bash
   serverless deploy
   ```

### Frontend Deployment (Vercel)

1. Create a `vercel.json` configuration:
   ```json
   {
     "version": 2,
     "routes": [
       { "src": "/api/(.*)", "dest": "https://your-lambda-url.amazonaws.com/api/$1" },
       { "src": "/(.*)", "dest": "/$1" }
     ]
   }
   ```

2. Deploy to Vercel:
   ```bash
   vercel --prod
   ```

## Monitoring and Maintenance

1. **Set up monitoring**:
   - Use CloudWatch for AWS deployments
   - Use Prometheus and Grafana for Docker deployments
   - Set up alerts for errors and performance issues

2. **Regular updates**:
   - Keep dependencies updated
   - Regularly retrain the machine learning models with new data
   - Update API keys as needed

3. **Backup strategy**:
   - Regularly backup the SQLite database
   - Consider using a more robust database for production (PostgreSQL, MySQL)

4. **Scaling considerations**:
   - For high traffic, consider scaling the backend horizontally
   - Use a load balancer for multiple backend instances
   - Consider caching common requests

## Security Considerations

1. **API Keys**:
   - Never commit API keys to the repository
   - Use environment variables or a secrets manager

2. **Database Security**:
   - Restrict access to the database
   - Use prepared statements to prevent SQL injection

3. **Input Validation**:
   - Validate all user input on both frontend and backend
   - Sanitize URLs before processing

4. **Rate Limiting**:
   - Implement rate limiting to prevent abuse
   - Consider using a service like AWS WAF or Cloudflare

5. **Regular Security Audits**:
   - Conduct regular security audits
   - Keep all dependencies updated to patch vulnerabilities
