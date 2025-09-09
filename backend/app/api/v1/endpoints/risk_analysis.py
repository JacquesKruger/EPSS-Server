"""
Risk Analysis Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
import structlog
from app.core.database import get_db
from app.services.vulnerability_service import vulnerability_service
from app.models.vulnerability import Asset, VulnerabilityFinding, Vulnerability

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def get_risk_analysis(db: Session = Depends(get_db)):
    """
    Get comprehensive risk analysis
    
    Returns:
        Risk analysis data including asset risk scores and vulnerability distribution
    """
    try:
        risk_analysis = await vulnerability_service.get_asset_risk_analysis()
        return risk_analysis
        
    except Exception as e:
        logger.error("Failed to get risk analysis", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve risk analysis")


@router.get("/assets")
async def get_asset_risk_scores(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    min_risk_score: Optional[float] = Query(None, ge=0, le=100),
    risk_level: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get asset risk scores with filtering
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        min_risk_score: Minimum risk score filter
        risk_level: Filter by risk level
        
    Returns:
        List of assets with risk scores
    """
    try:
        query = db.query(Asset)
        
        if min_risk_score:
            query = query.filter(Asset.asset_risk_score >= min_risk_score)
        
        if risk_level:
            query = query.filter(Asset.cpr_risk_level == risk_level)
        
        total = query.count()
        assets = query.offset(skip).limit(limit).all()
        
        # Calculate risk scores for assets that don't have them
        for asset in assets:
            if not asset.asset_risk_score:
                asset.asset_risk_score = await _calculate_asset_risk_score(db, asset)
                asset.cpr_risk_level = _determine_risk_level(asset.asset_risk_score)
        
        db.commit()
        
        return {
            "assets": [
                {
                    "ip_address": asset.ip_address,
                    "hostname": asset.hostname,
                    "asset_type": asset.asset_type,
                    "environment": asset.environment,
                    "business_criticality": asset.business_criticality,
                    "total_vulnerabilities": asset.total_vulnerabilities,
                    "critical_vulnerabilities": asset.critical_vulnerabilities,
                    "high_vulnerabilities": asset.high_vulnerabilities,
                    "medium_vulnerabilities": asset.medium_vulnerabilities,
                    "low_vulnerabilities": asset.low_vulnerabilities,
                    "asset_risk_score": asset.asset_risk_score,
                    "cpr_risk_level": asset.cpr_risk_level,
                    "last_scan": asset.last_scan,
                    "created_at": asset.created_at
                }
                for asset in assets
            ],
            "total": total,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error("Failed to get asset risk scores", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve asset risk scores")


@router.get("/assets/{ip_address}")
async def get_asset_details(
    ip_address: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific asset
    
    Args:
        ip_address: IP address of the asset
        
    Returns:
        Detailed asset information with vulnerabilities
    """
    try:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Get vulnerabilities for this asset
        findings = db.query(VulnerabilityFinding).join(Vulnerability).filter(
            VulnerabilityFinding.ip_address == ip_address
        ).all()
        
        # Group vulnerabilities by CVE
        vulnerabilities = {}
        for finding in findings:
            if finding.vulnerability:
                cve_id = finding.vulnerability.cve_id
                if cve_id not in vulnerabilities:
                    vulnerabilities[cve_id] = {
                        "cve_id": cve_id,
                        "title": finding.vulnerability.title,
                        "description": finding.vulnerability.description,
                        "cvss_score": finding.vulnerability.cvss_score,
                        "cvss_severity": finding.vulnerability.cvss_severity,
                        "epss_score": finding.vulnerability.epss_score,
                        "epss_percentile": finding.vulnerability.epss_percentile,
                        "cpr_score": finding.vulnerability.cpr_score,
                        "cpr_risk_level": finding.vulnerability.cpr_risk_level,
                        "ports": [],
                        "services": [],
                        "scan_count": 0
                    }
                
                if finding.port:
                    vulnerabilities[cve_id]["ports"].append(finding.port)
                if finding.service:
                    vulnerabilities[cve_id]["services"].append(finding.service)
                vulnerabilities[cve_id]["scan_count"] += 1
        
        # Calculate risk score if not set
        if not asset.asset_risk_score:
            asset.asset_risk_score = await _calculate_asset_risk_score(db, asset)
            asset.cpr_risk_level = _determine_risk_level(asset.asset_risk_score)
            db.commit()
        
        return {
            "asset": {
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "business_criticality": asset.business_criticality,
                "total_vulnerabilities": asset.total_vulnerabilities,
                "critical_vulnerabilities": asset.critical_vulnerabilities,
                "high_vulnerabilities": asset.high_vulnerabilities,
                "medium_vulnerabilities": asset.medium_vulnerabilities,
                "low_vulnerabilities": asset.low_vulnerabilities,
                "asset_risk_score": asset.asset_risk_score,
                "cpr_risk_level": asset.cpr_risk_level,
                "last_scan": asset.last_scan,
                "created_at": asset.created_at
            },
            "vulnerabilities": list(vulnerabilities.values()),
            "total_vulnerabilities": len(vulnerabilities),
            "total_findings": len(findings)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get asset details", ip_address=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve asset details")


@router.get("/trends")
async def get_risk_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """
    Get risk trends over time
    
    Args:
        days: Number of days to look back
        
    Returns:
        Risk trends data
    """
    try:
        from datetime import datetime, timedelta
        
        # Get date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get daily asset risk distribution
        daily_risk = {}
        for risk_level in ['critical', 'high', 'medium', 'low']:
            # This would require a more complex query to track historical risk levels
            # For now, we'll return current distribution
            count = db.query(Asset).filter(
                Asset.cpr_risk_level == risk_level
            ).count()
            daily_risk[risk_level] = count
        
        # Get vulnerability discovery trends
        daily_vulns = db.query(
            func.date(Vulnerability.created_at).label('date'),
            func.count(Vulnerability.id).label('count')
        ).filter(
            Vulnerability.created_at >= start_date
        ).group_by(
            func.date(Vulnerability.created_at)
        ).order_by('date').all()
        
        return {
            "period_days": days,
            "current_risk_distribution": daily_risk,
            "vulnerability_discovery_trend": [
                {"date": str(vuln.date), "count": vuln.count}
                for vuln in daily_vulns
            ]
        }
        
    except Exception as e:
        logger.error("Failed to get risk trends", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve risk trends")


async def _calculate_asset_risk_score(db: Session, asset: Asset) -> float:
    """
    Calculate risk score for an asset
    
    Args:
        db: Database session
        asset: Asset record
        
    Returns:
        Risk score (0-100)
    """
    try:
        # Get vulnerabilities for this asset
        findings = db.query(VulnerabilityFinding).join(Vulnerability).filter(
            VulnerabilityFinding.ip_address == asset.ip_address
        ).all()
        
        if not findings:
            return 0.0
        
        # Calculate weighted risk score
        total_score = 0.0
        total_weight = 0.0
        
        for finding in findings:
            if finding.vulnerability and finding.vulnerability.cpr_score:
                # Weight by severity
                weight = 1.0
                if finding.vulnerability.cvss_score:
                    if finding.vulnerability.cvss_score >= 9.0:
                        weight = 4.0  # Critical
                    elif finding.vulnerability.cvss_score >= 7.0:
                        weight = 3.0  # High
                    elif finding.vulnerability.cvss_score >= 4.0:
                        weight = 2.0  # Medium
                    else:
                        weight = 1.0  # Low
                
                total_score += finding.vulnerability.cpr_score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
        
    except Exception as e:
        logger.error("Failed to calculate asset risk score", error=str(e))
        return 0.0


def _determine_risk_level(risk_score: float) -> str:
    """
    Determine risk level based on risk score
    
    Args:
        risk_score: Risk score (0-100)
        
    Returns:
        Risk level string
    """
    if risk_score >= 90:
        return 'critical'
    elif risk_score >= 70:
        return 'high'
    elif risk_score >= 40:
        return 'medium'
    else:
        return 'low'
