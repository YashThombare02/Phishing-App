# PhishGuard Deployment Guide

This guide explains how to deploy the PhishGuard application to cloud services.

## Backend Deployment (Render)

1. **Create a Render Account**
   - Sign up at [render.com](https://render.com)

2. **Create a New Web Service**
   - Click "New" → "Web Service"
   - Connect your GitHub repository
   - Select the repository and branch

3. **Configure the Service**
   - Name: `phishguard-backend`
   - Environment: Python
   - Region: Choose the closest to your users
   - Branch: `main` or your deployment branch
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

4. **Set Environment Variables**
   - FLASK_ENV: `production`
   - CORS_ORIGINS: `https://phishguard.vercel.app,http://localhost:3000` (update with your frontend URL)
   - DB_TYPE: `sqlite` (or `postgres` if using a database add-on)
   - PHISHTANK_API_KEY: Your PhishTank API key (optional)
   - GOOGLE_SAFE_BROWSING_API_KEY: Your Google Safe Browsing API key (optional)

5. **Create and Deploy**
   - Click "Create Web Service"
   - Render will build and deploy your application

## Frontend Deployment (Vercel)

1. **Create a Vercel Account**
   - Sign up at [vercel.com](https://vercel.com)

2. **Install Vercel CLI (Optional)**
   ```
   npm install -g vercel
   ```

3. **Deploy from the Dashboard**
   - Click "New Project"
   - Import your repository
   - Configure project settings
   - Set environment variables:
     - NEXT_PUBLIC_API_URL: `https://phishguard-backend.onrender.com/api` (or your Render URL)

4. **Deploy**
   - Click "Deploy"

## Testing the Deployment

1. Open your deployed frontend URL
2. Try analyzing a URL
3. Verify that reports can be submitted and retrieved
4. Check that all features are working correctly

## Troubleshooting

- **CORS Issues**: Ensure CORS_ORIGINS in backend includes your frontend URL
- **API Connection Issues**: Check network tab for errors
- **Database Errors**: Check Render logs for database connection issues