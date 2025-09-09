# CPR Score Server - Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### Prerequisites
- Docker and Docker Compose
- Git

### 1. Clone and Setup
```bash
git clone <repository-url>
cd cpr-score-server
cp env.example .env
```

### 2. Start the Application
```bash
docker-compose up -d
```

### 3. Access the Application
- **Frontend**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### 4. Upload Your First CSV
1. Go to http://localhost:3000/upload
2. Select scanner type (Wazuh or OpenVAS)
3. Upload your CSV file
4. Monitor processing status

### 5. View Results
1. Check the Dashboard for overview
2. Browse Vulnerabilities for detailed CVE data
3. Review Risk Analysis for asset risk scores
4. Generate Reports for documentation

## 📊 What You Get

### Core Features
- ✅ **CSV Upload**: Support for Wazuh and OpenVAS formats
- ✅ **EPSS Integration**: Automatic EPSS score retrieval
- ✅ **CPR Scoring**: Advanced risk calculation algorithm
- ✅ **Interactive Dashboard**: Real-time vulnerability overview
- ✅ **Risk Analysis**: Asset-based risk assessment
- ✅ **Report Generation**: PDF/Excel reports

### Sample Data
The system comes with sample data to demonstrate functionality:
- 1,000+ sample vulnerabilities
- Multiple risk levels (Critical, High, Medium, Low)
- Asset risk scoring
- Trend analysis

## 🔧 Configuration

### Environment Variables
Edit `.env` file to customize:
```env
# Database
DATABASE_URL=postgresql://cpr_user:cpr_password@postgres:5432/cpr_score_db

# API Keys (Optional)
EPSS_API_KEY=your_epss_api_key
CVE_API_KEY=your_cve_api_key

# CPR Score Weights
CVSS_WEIGHT=0.6
EPSS_WEIGHT=0.4
```

### CPR Score Algorithm
```
CPR = (CVSS_Percentile × 0.6) + (EPSS_Percentile × 0.4)
```

Risk Levels:
- **Critical (90-100)**: Immediate action required
- **High (70-89)**: Address within 24-48 hours
- **Medium (40-69)**: Address within 1-2 weeks
- **Low (0-39)**: Monitor and address during maintenance

## 📈 Understanding the Dashboard

### Key Metrics
- **Total Vulnerabilities**: Count of all discovered vulnerabilities
- **Critical Vulnerabilities**: High-risk vulnerabilities requiring immediate attention
- **High Risk Assets**: Systems with elevated risk scores
- **Assets Monitored**: Total number of systems being tracked

### Charts and Visualizations
- **Vulnerability Trends**: Time-series analysis of vulnerability discovery
- **Risk Distribution**: Breakdown of assets by risk level
- **Recent Scans**: Latest vulnerability scan results
- **Top Risky Assets**: Systems with highest risk scores

## 🛠️ Development

### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend Development
```bash
cd frontend
npm install
npm start
```

### Database Management
```bash
# Access PostgreSQL
docker exec -it cpr-postgres psql -U cpr_user -d cpr_score_db

# Run migrations
docker exec -it cpr-backend alembic upgrade head
```

## 🔍 API Usage

### Upload CSV
```bash
curl -X POST "http://localhost:8000/api/v1/upload/csv" \
  -F "file=@vulnerabilities.csv" \
  -F "scan_type=wazuh" \
  -F "scan_name=Production Scan"
```

### Get Vulnerabilities
```bash
curl "http://localhost:8000/api/v1/vulnerabilities?risk_level=critical&limit=10"
```

### Generate Report
```bash
curl -X POST "http://localhost:8000/api/v1/reports/generate" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "executive", "format": "pdf"}'
```

## 🚨 Troubleshooting

### Common Issues

#### Database Connection Error
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Restart database
docker-compose restart postgres
```

#### File Upload Fails
- Ensure CSV file is properly formatted
- Check file size (max 50MB)
- Verify scanner type matches CSV format

#### EPSS API Errors
- Check internet connectivity
- Verify API key if using paid tier
- Check API rate limits

### Logs
```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs backend
docker-compose logs frontend
```

## 📚 Next Steps

### 1. Customize Configuration
- Adjust CPR score weights
- Configure risk thresholds
- Set up email notifications

### 2. Integrate with Your Environment
- Connect to your SIEM
- Set up automated scans
- Configure ticketing system integration

### 3. Scale the System
- Set up load balancing
- Configure database clustering
- Implement caching strategies

### 4. Advanced Features
- Set up machine learning models
- Configure threat intelligence feeds
- Implement compliance frameworks

## 🆘 Support

### Documentation
- **API Docs**: http://localhost:8000/docs
- **README**: See main README.md
- **Additional Features**: See ADDITIONAL_FEATURES.md

### Getting Help
- Check the logs for error messages
- Review the API documentation
- Create an issue in the repository

### Community
- Join our Discord server
- Follow us on Twitter
- Star the repository on GitHub

## 🎯 Success Metrics

After setup, you should see:
- ✅ Application accessible at http://localhost:3000
- ✅ API responding at http://localhost:8000/health
- ✅ Database connected and tables created
- ✅ Sample data loaded (if available)
- ✅ CSV upload functionality working
- ✅ Dashboard displaying vulnerability data

Welcome to CPR Score Server! 🛡️
