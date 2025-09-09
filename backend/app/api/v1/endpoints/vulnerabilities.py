"""
Vulnerability Management Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List
from sqlalchemy.orm import Session
import structlog
from app.core.database import get_db
from app.services.vulnerability_service import vulnerability_service
from app.models.vulnerability import Vulnerability

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    risk_level: Optional[str] = Query(None),
    min_cpr_score: Optional[float] = Query(None, ge=0, le=100),
    cve_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get vulnerabilities with CPR scores
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        risk_level: Filter by risk level (critical, high, medium, low)
        min_cpr_score: Minimum CPR score filter
        cve_id: Filter by specific CVE ID
        
    Returns:
        List of vulnerabilities with CPR scores
    """
    try:
        if cve_id:
            # Get specific vulnerability
            vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
            if not vuln:
                raise HTTPException(status_code=404, detail="Vulnerability not found")
            
            return {
                "vulnerability": {
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "description": vuln.description,
                    "cvss_score": vuln.cvss_score,
                    "cvss_severity": vuln.cvss_severity,
                    "cvss_vector": vuln.cvss_vector,
                    "epss_score": vuln.epss_score,
                    "epss_percentile": vuln.epss_percentile,
                    "cpr_score": vuln.cpr_score,
                    "cpr_risk_level": vuln.cpr_risk_level,
                    "created_at": vuln.created_at,
                    "updated_at": vuln.updated_at,
                    "last_epss_update": vuln.last_epss_update
                }
            }
        else:
            # Get vulnerabilities with filters
            result = await vulnerability_service.get_vulnerabilities_with_cpr_scores(
                skip=skip,
                limit=limit,
                risk_level=risk_level,
                min_cpr_score=min_cpr_score
            )
            return result
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get vulnerabilities", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")


@router.get("/statistics")
async def get_vulnerability_statistics(db: Session = Depends(get_db)):
    """
    Get vulnerability statistics
    
    Returns:
        Vulnerability statistics
    """
    try:
        # Get total counts
        total_vulns = db.query(Vulnerability).count()
        vulns_with_cpr = db.query(Vulnerability).filter(
            Vulnerability.cpr_score.isnot(None)
        ).count()
        
        # Get risk level distribution
        risk_distribution = {}
        for risk_level in ['critical', 'high', 'medium', 'low']:
            count = db.query(Vulnerability).filter(
                Vulnerability.cpr_risk_level == risk_level
            ).count()
            risk_distribution[risk_level] = count
        
        # Get CVSS severity distribution
        severity_distribution = {}
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = db.query(Vulnerability).filter(
                Vulnerability.cvss_severity == severity
            ).count()
            severity_distribution[severity.lower()] = count
        
        # Get average scores
        avg_cvss = db.query(Vulnerability).filter(
            Vulnerability.cvss_score.isnot(None)
        ).with_entities(
            db.func.avg(Vulnerability.cvss_score)
        ).scalar() or 0
        
        avg_epss = db.query(Vulnerability).filter(
            Vulnerability.epss_score.isnot(None)
        ).with_entities(
            db.func.avg(Vulnerability.epss_score)
        ).scalar() or 0
        
        avg_cpr = db.query(Vulnerability).filter(
            Vulnerability.cpr_score.isnot(None)
        ).with_entities(
            db.func.avg(Vulnerability.cpr_score)
        ).scalar() or 0
        
        return {
            "total_vulnerabilities": total_vulns,
            "vulnerabilities_with_cpr": vulns_with_cpr,
            "risk_distribution": risk_distribution,
            "severity_distribution": severity_distribution,
            "average_scores": {
                "cvss": round(avg_cvss, 2),
                "epss": round(avg_epss, 4),
                "cpr": round(avg_cpr, 2)
            }
        }
        
    except Exception as e:
        logger.error("Failed to get vulnerability statistics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.get("/trends")
async def get_vulnerability_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """
    Get vulnerability trends over time
    
    Args:
        days: Number of days to look back
        
    Returns:
        Vulnerability trends data
    """
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func
        
        # Get date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get daily vulnerability counts
        daily_counts = db.query(
            func.date(Vulnerability.created_at).label('date'),
            func.count(Vulnerability.id).label('count')
        ).filter(
            Vulnerability.created_at >= start_date
        ).group_by(
            func.date(Vulnerability.created_at)
        ).order_by('date').all()
        
        # Get daily risk level distribution
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
            "period_days": days,
            "daily_counts": [
                {"date": str(count.date), "count": count.count}
                for count in daily_counts
            ],
            "daily_risk_distribution": daily_risk
        }
        
    except Exception as e:
        logger.error("Failed to get vulnerability trends", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve trends")


@router.get("/search")
async def search_vulnerabilities(
    q: str = Query(..., min_length=3),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Search vulnerabilities by CVE ID, title, or description
    
    Args:
        q: Search query
        limit: Maximum number of results
        
    Returns:
        Search results
    """
    try:
        from sqlalchemy import or_
        
        # Search in CVE ID, title, and description
        vulnerabilities = db.query(Vulnerability).filter(
            or_(
                Vulnerability.cve_id.ilike(f"%{q}%"),
                Vulnerability.title.ilike(f"%{q}%"),
                Vulnerability.description.ilike(f"%{q}%")
            )
        ).limit(limit).all()
        
        return {
            "query": q,
            "results": [
                {
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "cvss_score": vuln.cvss_score,
                    "cvss_severity": vuln.cvss_severity,
                    "cpr_score": vuln.cpr_score,
                    "cpr_risk_level": vuln.cpr_risk_level
                }
                for vuln in vulnerabilities
            ],
            "total": len(vulnerabilities)
        }
        
    except Exception as e:
        logger.error("Failed to search vulnerabilities", error=str(e), query=q)
        raise HTTPException(status_code=500, detail="Search failed")


@router.get("/{cve_id}/details")
async def get_vulnerability_details(
    cve_id: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific vulnerability
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        Detailed vulnerability information
    """
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Get related findings
        findings = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.vulnerability_id == vuln.id
        ).all()
        
        # Get affected assets
        affected_assets = {}
        for finding in findings:
            ip = finding.ip_address
            if ip not in affected_assets:
                affected_assets[ip] = {
                    "ip_address": ip,
                    "hostname": finding.hostname,
                    "ports": [],
                    "services": [],
                    "scan_count": 0
                }
            
            if finding.port:
                affected_assets[ip]["ports"].append(finding.port)
            if finding.service:
                affected_assets[ip]["services"].append(finding.service)
            affected_assets[ip]["scan_count"] += 1
        
        return {
            "vulnerability": {
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "description": vuln.description,
                "cvss_score": vuln.cvss_score,
                "cvss_severity": vuln.cvss_severity,
                "cvss_vector": vuln.cvss_vector,
                "epss_score": vuln.epss_score,
                "epss_percentile": vuln.epss_percentile,
                "cpr_score": vuln.cpr_score,
                "cpr_risk_level": vuln.cpr_risk_level,
                "created_at": vuln.created_at,
                "updated_at": vuln.updated_at,
                "last_epss_update": vuln.last_epss_update
            },
            "affected_assets": list(affected_assets.values()),
            "total_findings": len(findings),
            "unique_assets": len(affected_assets)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get vulnerability details", cve_id=cve_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerability details")
