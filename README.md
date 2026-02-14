# CPR Score Server

A comprehensive vulnerability assessment platform that combines CVSS (Common Vulnerability Scoring System) and EPSS (Exploit Prediction Scoring System) scores to calculate CPR (Cybersecurity Priority Risk) scores for enhanced threat prioritization.

## 🎯 Project Overview

The CPR Score Server processes vulnerability data from Wazuh and OpenVAS CSV exports, enriches it with EPSS scores, and provides actionable insights through an intuitive dashboard and downloadable reports.

## ✨ Key Features

### Core Functionality
- **CSV Upload & Processing**: Support for Wazuh and OpenVAS vulnerability exports
- **CVE Enrichment**: Automatic EPSS score retrieval for unique CVEs
- **CPR Score Calculation**: Advanced algorithm combining CVSS and EPSS percentiles
- **Interactive Dashboard**: Real-time visualization of vulnerability data
- **Downloadable Reports**: Comprehensive PDF/Excel reports with actionable insights

### Risk Assessment
- **IP Risk Analysis**: Identify at-risk systems based on CPR and EPSS scores
- **Vulnerability Prioritization**: Sort vulnerabilities by risk level
- **Trend Analysis**: Track vulnerability trends over time
- **Asset Impact Assessment**: Understand business impact of vulnerabilities

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Data Layer    │
│   (React)       │◄──►│   (FastAPI)     │◄──►│   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  External APIs  │
                       │  (EPSS, CVE DB) │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 16+
- PostgreSQL 13+
- Docker (optional)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd cpr-score-server
```

2. **Backend Setup**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Database Setup**
```bash
# Create database
createdb cpr_score_db

# Run migrations
alembic upgrade head
```

4. **Frontend Setup**
```bash
cd frontend
npm install
```

5. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your configuration
```

### Running the Application

1. **Start the backend**
```bash
cd backend
uvicorn main:app --reload
```

2. **Start the frontend**
```bash
cd frontend
npm start
```

3. **Access the application**
- Frontend: http://localhost:3000
- API Documentation: http://localhost:8000/docs

## 📊 CPR Score Algorithm

The CPR (Cybersecurity Priority Risk) score is calculated using a weighted combination of CVSS and EPSS scores:

```
CPR = (CVSS_Percentile × 0.6) + (EPSS_Percentile × 0.4)
```

Where:
- **CVSS_Percentile**: Normalized CVSS score (0-100)
- **EPSS_Percentile**: EPSS score converted to percentile (0-100)
- **Weights**: Configurable based on organizational priorities

### Risk Categories
- **Critical (90-100)**: Immediate action required
- **High (70-89)**: Address within 24-48 hours
- **Medium (40-69)**: Address within 1-2 weeks
- **Low (0-39)**: Monitor and address during regular maintenance

## 📁 Project Structure

```
cpr-score-server/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── services/
│   │   └── utils/
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── utils/
│   └── package.json
├── docs/
├── docker/
└── README.md
```

## 🔧 Configuration

### Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/cpr_score_db

# API Keys
EPSS_API_KEY=your_epss_api_key
CVE_API_KEY=your_cve_api_key

# Security
SECRET_KEY=your_secret_key
JWT_SECRET=your_jwt_secret

# Application
DEBUG=True
LOG_LEVEL=INFO
```

## 📈 Additional Features

### Advanced Analytics
- **Vulnerability Trends**: Track CVE discovery and remediation over time
- **Asset Risk Scoring**: Calculate risk scores for entire systems/networks
- **Compliance Mapping**: Map vulnerabilities to compliance frameworks (NIST, ISO 27001)
- **Threat Intelligence Integration**: Enrich with threat actor information

### Automation & Integration
- **Scheduled Scans**: Automated vulnerability assessment workflows
- **SIEM Integration**: Export data to Splunk, QRadar, etc.
- **Ticketing System Integration**: Create tickets in Jira, ServiceNow
- **Email Notifications**: Alert on high-risk vulnerabilities

### Reporting & Visualization
- **Executive Dashboards**: High-level risk overview for management
- **Technical Reports**: Detailed technical analysis for security teams
- **Custom Report Templates**: Configurable report formats
- **Data Export**: CSV, JSON, XML export capabilities

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test

# Integration tests
pytest tests/integration/
```

## 📝 API Documentation

The API documentation is available at `/docs` when running the backend server. Key endpoints include:

- `POST /api/v1/upload` - Upload CSV files
- `GET /api/v1/vulnerabilities` - Retrieve vulnerability data
- `GET /api/v1/cpr-scores` - Get CPR score calculations
- `GET /api/v1/reports` - Generate reports
- `GET /api/v1/risk-analysis` - Get risk analysis data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.



## 🔮 Roadmap

### Phase 1 (Current)
- [x] Basic CSV upload and processing
- [x] EPSS integration
- [x] CPR score calculation
- [x] Basic dashboard

### Phase 2
- [ ] Advanced analytics
- [ ] SIEM integration
- [ ] Automated reporting
- [ ] Mobile app

### Phase 3
- [ ] Machine learning predictions
- [ ] Advanced threat intelligence
- [ ] Multi-tenant support
- [ ] Enterprise features
