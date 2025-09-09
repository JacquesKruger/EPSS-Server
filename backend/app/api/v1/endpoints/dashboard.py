"""
Dashboard Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import structlog
from app.core.database import get_db
from app.models.vulnerability import Vulnerability, Scan, Asset, VulnerabilityFinding
from app.services.vulnerability_service import vulnerability_service

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def get_dashboard_data(db: Session = Depends(get_db)):
    """
    Get dashboard overview data
    
    Returns:
        Dashboard data including statistics, trends, and recent activity
    """
    try:
        # Get basic statistics
        statistics = await _get_statistics(db)
        
        # Get vulnerability trends
        vulnerability_trends = await _get_vulnerability_trends(db)
        
        # Get recent scans
        recent_scans = await _get_recent_scans(db)
        
        # Get risk analysis
        risk_analysis = await vulnerability_service.get_asset_risk_analysis()
        
        return {
            "statistics": statistics,
            "vulnerability_trends": vulnerability_trends,
            "recent_scans": recent_scans,
            "risk_analysis": risk_analysis,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to get dashboard data", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard data")


async def _get_statistics(db: Session) -> dict:
    """Get basic vulnerability statistics"""
    try:
        # Total vulnerabilities
        total_vulnerabilities = db.query(Vulnerability).count()
        
        # Vulnerabilities with CPR scores
        vulns_with_cpr = db.query(Vulnerability).filter(
            Vulnerability.cpr_score.isnot(None)
        ).count()
        
        # Risk level counts
        critical_vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.cpr_risk_level == 'critical'
        ).count()
        
        high_vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.cpr_risk_level == 'high'
        ).count()
        
        medium_vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.cpr_risk_level == 'medium'
        ).count()
        
        low_vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.cpr_risk_level == 'low'
        ).count()
        
        # CVSS severity counts
        critical_cvss = db.query(Vulnerability).filter(
            Vulnerability.cvss_severity == 'Critical'
        ).count()
        
        high_cvss = db.query(Vulnerability).filter(
            Vulnerability.cvss_severity == 'High'
        ).count()
        
        medium_cvss = db.query(Vulnerability).filter(
            Vulnerability.cvss_severity == 'Medium'
        ).count()
        
        low_cvss = db.query(Vulnerability).filter(
            Vulnerability.cvss_severity == 'Low'
        ).count()
        
        # Average scores
        avg_cvss = db.query(func.avg(Vulnerability.cvss_score)).filter(
            Vulnerability.cvss_score.isnot(None)
        ).scalar() or 0
        
        avg_epss = db.query(func.avg(Vulnerability.epss_score)).filter(
            Vulnerability.epss_score.isnot(None)
        ).scalar() or 0
        
        avg_cpr = db.query(func.avg(Vulnerability.cpr_score)).filter(
            Vulnerability.cpr_score.isnot(None)
        ).scalar() or 0
        
        return {
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerabilities_with_cpr": vulns_with_cpr,
            "critical_vulnerabilities": critical_vulnerabilities,
            "high_vulnerabilities": high_vulnerabilities,
            "medium_vulnerabilities": medium_vulnerabilities,
            "low_vulnerabilities": low_vulnerabilities,
            "cvss_severity_counts": {
                "critical": critical_cvss,
                "high": high_cvss,
                "medium": medium_cvss,
                "low": low_cvss
            },
            "average_scores": {
                "cvss": round(avg_cvss, 2),
                "epss": round(avg_epss, 4),
                "cpr": round(avg_cpr, 2)
            }
        }
        
    except Exception as e:
        logger.error("Failed to get statistics", error=str(e))
        return {}


async def _get_vulnerability_trends(db: Session) -> dict:
    """Get vulnerability trends over the last 30 days"""
    try:
        # Get date range (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # Daily vulnerability counts
        daily_counts = db.query(
            func.date(Vulnerability.created_at).label('date'),
            func.count(Vulnerability.id).label('count')
        ).filter(
            Vulnerability.created_at >= start_date
        ).group_by(
            func.date(Vulnerability.created_at)
        ).order_by('date').all()
        
        # Daily risk level distribution
        daily_risk = {}
        for risk_level in ['critical', 'high', 'medium', 'low']:
            counts = db.query(
                func.date(Vulnerability.created_at).label('date'),
                func.count(Vulnerability.id).label('count')
            ).filter(
                Vulnerability.created_at >= start_date,
                Vulnerability.cpr_risk_level == risk_level
            ).group_by(
                func.date(Vulnerability.created_at)
            ).order_by('date').all()
            
            daily_risk[risk_level] = [
                {"date": str(count.date), "count": count.count}
                for count in counts
            ]
        
        return {
            "daily_counts": [
                {"date": str(count.date), "count": count.count}
                for count in daily_counts
            ],
            "daily_risk_distribution": daily_risk,
            "period_days": 30
        }
        
    except Exception as e:
        logger.error("Failed to get vulnerability trends", error=str(e))
        return {}


async def _get_recent_scans(db: Session) -> list:
    """Get recent scan information"""
    try:
        # Get last 10 scans
        scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(10).all()
        
        return [
            {
                "scan_id": scan.id,
                "name": scan.name,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "total_findings": scan.total_findings,
                "unique_cves": scan.unique_cves,
                "high_severity_count": scan.high_severity_count,
                "medium_severity_count": scan.medium_severity_count,
                "low_severity_count": scan.low_severity_count,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error_message": scan.error_message
            }
            for scan in scans
        ]
        
    except Exception as e:
        logger.error("Failed to get recent scans", error=str(e))
        return []


@router.get("/summary")
async def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Get quick dashboard summary for widgets
    
    Returns:
        Summary data for dashboard widgets
    """
    try:
        # Get counts
        total_vulns = db.query(Vulnerability).count()
        critical_vulns = db.query(Vulnerability).filter(
            Vulnerability.cpr_risk_level == 'critical'
        ).count()
        total_assets = db.query(Asset).count()
        active_scans = db.query(Scan).filter(
            Scan.status == 'processing'
        ).count()
        
        # Get recent activity
        recent_vulns = db.query(Vulnerability).order_by(
            desc(Vulnerability.created_at)
        ).limit(5).all()
        
        recent_scans = db.query(Scan).order_by(
            desc(Scan.started_at)
        ).limit(5).all()
        
        return {
            "counts": {
                "total_vulnerabilities": total_vulns,
                "critical_vulnerabilities": critical_vulns,
                "total_assets": total_assets,
                "active_scans": active_scans
            },
            "recent_vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "cpr_score": vuln.cpr_score,
                    "cpr_risk_level": vuln.cpr_risk_level,
                    "created_at": vuln.created_at
                }
                for vuln in recent_vulns
            ],
            "recent_scans": [
                {
                    "name": scan.name,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "total_findings": scan.total_findings,
                    "started_at": scan.started_at
                }
                for scan in recent_scans
            ]
        }
        
    except Exception as e:
        logger.error("Failed to get dashboard summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard summary")
