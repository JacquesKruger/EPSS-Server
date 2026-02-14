"""
Vulnerability Management Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List
from sqlalchemy.orm import Session
import structlog
from app.core.database import get_db
from app.services.vulnerability_service import vulnerability_service
from app.models.vulnerability import Vulnerability, VulnerabilityFinding

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    # limit = -1 means "return all"
    limit: int = Query(100, ge=-1, le=10000),
    risk_level: Optional[str] = Query(None),
    min_cpr_score: Optional[float] = Query(None, ge=0, le=100),
    cve_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    scan_id: Optional[int] = Query(None),
    sort_by: Optional[str] = Query("cpr_score"),
    sort_order: Optional[str] = Query("desc"),
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
            # Get all vulnerabilities with basic filters
            query = db.query(Vulnerability)
            
            # Apply filters
            if risk_level:
                query = query.filter(Vulnerability.cvss_severity.ilike(f"%{risk_level}%"))
            
            if severity:
                query = query.filter(Vulnerability.cvss_severity.ilike(f"%{severity}%"))
            
            if min_cpr_score:
                query = query.filter(Vulnerability.cpr_score >= min_cpr_score)
            
            if search:
                from sqlalchemy import or_
                query = query.filter(
                    or_(
                        Vulnerability.cve_id.ilike(f"%{search}%"),
                        Vulnerability.title.ilike(f"%{search}%"),
                        Vulnerability.description.ilike(f"%{search}%")
                    )
                )
            
            # Filter by scan_id if provided
            if scan_id:
                from app.models.vulnerability import VulnerabilityFinding, Scan
                # Get vulnerabilities that have findings in the specified scan
                # Use subquery to avoid duplicates from JOIN
                subquery = db.query(VulnerabilityFinding.vulnerability_id).join(Scan).filter(Scan.id == scan_id).subquery()
                query = query.filter(Vulnerability.id.in_(subquery))
            
            # Apply sorting
            if sort_by == "cpr_score":
                if sort_order == "asc":
                    query = query.order_by(Vulnerability.cpr_score.asc().nulls_last())
                else:
                    query = query.order_by(Vulnerability.cpr_score.desc().nulls_last())
            elif sort_by == "cvss_score":
                if sort_order == "asc":
                    query = query.order_by(Vulnerability.cvss_score.asc().nulls_last())
                else:
                    query = query.order_by(Vulnerability.cvss_score.desc().nulls_last())
            elif sort_by == "epss_score":
                if sort_order == "asc":
                    query = query.order_by(Vulnerability.epss_score.asc().nulls_last())
                else:
                    query = query.order_by(Vulnerability.epss_score.desc().nulls_last())
            elif sort_by == "cve_id":
                if sort_order == "asc":
                    query = query.order_by(Vulnerability.cve_id.asc())
                else:
                    query = query.order_by(Vulnerability.cve_id.desc())
            else:
                # Default sorting by CPR Score descending
                query = query.order_by(Vulnerability.cpr_score.desc().nulls_last())
            
            total = query.count()
            if limit == -1:
                # Return all matching rows (no pagination)
                vulnerabilities = query.all()
            else:
                vulnerabilities = query.offset(skip).limit(limit).all()
            
            # Get findings count for each vulnerability
            from app.models.vulnerability import VulnerabilityFinding
            from sqlalchemy import func
            vuln_ids = [vuln.id for vuln in vulnerabilities]
            findings_counts = db.query(
                VulnerabilityFinding.vulnerability_id,
                func.count(VulnerabilityFinding.id).label('count')
            ).filter(
                VulnerabilityFinding.vulnerability_id.in_(vuln_ids)
            ).group_by(VulnerabilityFinding.vulnerability_id).all()
            
            # Create a mapping of vulnerability_id to findings count
            findings_map = {vf.vulnerability_id: vf.count for vf in findings_counts}
            
            # Set findings count for each vulnerability
            for vuln in vulnerabilities:
                vuln.findings_count = findings_map.get(vuln.id, 0)
            
            return {
                "vulnerabilities": [
                    {
                        "id": vuln.id,
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
                        "last_epss_update": vuln.last_epss_update,
                        "findings_count": getattr(vuln, 'findings_count', 0)
                    }
                    for vuln in vulnerabilities
                ],
                "total": total,
                "skip": skip,
                "limit": limit
            }
            
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
