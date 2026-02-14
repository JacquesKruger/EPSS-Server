# CPR Score Server - Quick Start Guide

## 🚀 Getting Started in Minutes

### Prerequisites
- Docker and Docker Compose
- Git

### 1) Clone and configure
```bash
git clone <repository-url>
cd EPSS-Server
cp .env.example .env  # if provided; otherwise see variables below
```

Minimal `.env` values (sane defaults are used if omitted):
```env
# Database (works with the default docker-compose.yml)
DATABASE_URL=postgresql://user:password@postgres:5432/cpr_score_db

# Optional external API keys
EPSS_API_KEY=
CVE_API_KEY=

# CPR scoring weights
CVSS_WEIGHT=0.6
EPSS_WEIGHT=0.4
```

### 2) Start the stack
```bash
docker-compose up -d
```

Services/ports:
- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health:   http://localhost:8000/health

### 3) Upload your first scan
1. Go to http://localhost:3000/upload
2. Choose scan type: Manual, Wazuh, or OpenVAS
3. Select your CSV and submit
4. Once processing completes, a new scan will appear on the Reports page

### 4) Explore results
- Reports: list of scans with counts and severity breakdown. Use “View Results” to open the Vulnerabilities view for that scan.
- Vulnerabilities: sortable/paginated table with CVE, CVSS, EPSS, CPR, and findings count. Supports search and severity filtering.
- Export: download a scan to CSV from Reports (or directly via the API below).

## 🔧 Configuration & Operations

### Useful commands
```bash
# Show service status and logs
docker-compose ps
docker-compose logs backend | tail -n 100

# Restart a service
docker-compose restart backend
```

### CSV formats (minimum required)
- Manual: CVE ID, Title, CVSS Score, Severity
- Wazuh: CVE (vulnerability.id), Hostname/agent.name (used as asset key)
- OpenVAS: NVT Name and IP. CVEs, severity and CVSS are used when present; CVE can be extracted from NVT name.

## 🔍 API quick reference

### Upload CSV
```bash
curl -X POST "http://localhost:8000/api/v1/upload/csv" \
  -F "file=@vulnerabilities.csv" \
  -F "scan_type=manual" \
  -F "scan_name=My Scan"
```

### List vulnerabilities
```bash
curl "http://localhost:8000/api/v1/vulnerabilities/?scan_id=18&limit=20"
```

### Export a scan to CSV
```bash
curl -L "http://localhost:8000/api/v1/reports/export/scan/18" -o scan_18.csv
```

## 🚨 Troubleshooting

**Database connection**
```bash
docker-compose ps postgres
docker-compose restart postgres
```

**CSV upload fails**
- Verify the columns match the selected scan type
- Ensure file size < 50 MB

**EPSS shows 0 for most CVEs**
- Check internet connectivity
- The server batches EPSS API calls; temporary rate limits can delay results

**Where are logs?**
```bash
docker-compose logs backend
docker-compose logs frontend
```

## ✅ You’re ready
- Frontend at http://localhost:3000
- API at http://localhost:8000
- Upload scans, view results, and export CSVs.

Welcome to CPR Score Server! 🛡️
