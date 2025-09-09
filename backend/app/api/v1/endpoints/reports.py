"""
Report Generation Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse
from typing import Optional, List
from sqlalchemy.orm import Session
import structlog
import os
import tempfile
from datetime import datetime
from app.core.database import get_db
from app.models.vulnerability import Report, Vulnerability, Scan, Asset
from app.services.report_service import report_service

router = APIRouter()
logger = structlog.get_logger()


@router.post("/generate")
async def generate_report(
    background_tasks: BackgroundTasks,
    report_type: str,
    format: str = "pdf",
    scan_ids: Optional[List[int]] = None,
    filters: Optional[dict] = None,
    db: Session = Depends(get_db)
):
    """
    Generate a new report
    
    Args:
        report_type: Type of report (executive, technical, compliance)
        format: Report format (pdf, excel, csv)
        scan_ids: List of scan IDs to include
        filters: Additional filters to apply
        
    Returns:
        Report generation status
    """
    try:
        # Validate report type
        valid_types = ['executive', 'technical', 'compliance']
        if report_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid report type. Valid types: {valid_types}"
            )
        
        # Validate format
        valid_formats = ['pdf', 'excel', 'csv']
        if format not in valid_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid format. Valid formats: {valid_formats}"
            )
        
        # Create report record
        report_name = f"{report_type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report = Report(
            name=report_name,
            report_type=report_type,
            format=format,
            scan_ids=str(scan_ids) if scan_ids else None,
            filters=str(filters) if filters else None,
            status="generating"
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        
        # Generate report in background
        background_tasks.add_task(
            generate_report_task,
            report.id,
            report_type,
            format,
            scan_ids,
            filters
        )
        
        logger.info(
            "Report generation initiated",
            report_id=report.id,
            report_type=report_type,
            format=format
        )
        
        return {
            "message": "Report generation started",
            "report_id": report.id,
            "report_name": report_name,
            "status": "generating"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to initiate report generation", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate report")


async def generate_report_task(
    report_id: int,
    report_type: str,
    format: str,
    scan_ids: Optional[List[int]],
    filters: Optional[dict]
):
    """
    Background task to generate report
    
    Args:
        report_id: ID of the report record
        report_type: Type of report
        format: Report format
        scan_ids: List of scan IDs
        filters: Additional filters
    """
    try:
        # Generate the report
        file_path = await report_service.generate_report(
            report_type=report_type,
            format=format,
            scan_ids=scan_ids,
            filters=filters
        )
        
        # Update report record
        db = next(get_db())
        try:
            report = db.query(Report).filter(Report.id == report_id).first()
            if report:
                report.status = "completed"
                report.file_path = file_path
                report.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                report.completed_at = datetime.now()
                report.expires_at = datetime.now() + timedelta(days=7)  # Expire in 7 days
                db.commit()
                
                logger.info(
                    "Report generation completed",
                    report_id=report_id,
                    file_path=file_path
                )
        finally:
            db.close()
            
    except Exception as e:
        logger.error(
            "Report generation failed",
            report_id=report_id,
            error=str(e)
        )
        
        # Update report status to failed
        db = next(get_db())
        try:
            report = db.query(Report).filter(Report.id == report_id).first()
            if report:
                report.status = "failed"
                report.error_message = str(e)
                db.commit()
        finally:
            db.close()


@router.get("/")
async def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    report_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    List generated reports
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        report_type: Filter by report type
        status: Filter by status
        
    Returns:
        List of reports
    """
    try:
        query = db.query(Report)
        
        if report_type:
            query = query.filter(Report.report_type == report_type)
        
        if status:
            query = query.filter(Report.status == status)
        
        total = query.count()
        reports = query.offset(skip).limit(limit).order_by(Report.created_at.desc()).all()
        
        return {
            "reports": [
                {
                    "report_id": report.id,
                    "name": report.name,
                    "report_type": report.report_type,
                    "format": report.format,
                    "status": report.status,
                    "file_size": report.file_size,
                    "created_at": report.created_at,
                    "completed_at": report.completed_at,
                    "expires_at": report.expires_at,
                    "error_message": report.error_message
                }
                for report in reports
            ],
            "total": total,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error("Failed to list reports", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Download a generated report
    
    Args:
        report_id: ID of the report
        
    Returns:
        Report file
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if report.status != "completed":
            raise HTTPException(
                status_code=400,
                detail=f"Report is not ready. Status: {report.status}"
            )
        
        if not report.file_path or not os.path.exists(report.file_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        # Check if report has expired
        if report.expires_at and datetime.now() > report.expires_at:
            raise HTTPException(status_code=410, detail="Report has expired")
        
        # Determine media type
        media_types = {
            'pdf': 'application/pdf',
            'excel': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'csv': 'text/csv'
        }
        
        media_type = media_types.get(report.format, 'application/octet-stream')
        
        return FileResponse(
            path=report.file_path,
            media_type=media_type,
            filename=f"{report.name}.{report.format}",
            headers={
                "Content-Disposition": f"attachment; filename={report.name}.{report.format}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to download report", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to download report")


@router.get("/{report_id}/status")
async def get_report_status(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Get report generation status
    
    Args:
        report_id: ID of the report
        
    Returns:
        Report status information
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        return {
            "report_id": report.id,
            "name": report.name,
            "report_type": report.report_type,
            "format": report.format,
            "status": report.status,
            "file_size": report.file_size,
            "created_at": report.created_at,
            "completed_at": report.completed_at,
            "expires_at": report.expires_at,
            "error_message": report.error_message
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get report status", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve report status")


@router.delete("/{report_id}")
async def delete_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a report and its file
    
    Args:
        report_id: ID of the report
        
    Returns:
        Deletion confirmation
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Delete file if it exists
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except Exception as e:
                logger.warning("Failed to delete report file", file_path=report.file_path, error=str(e))
        
        # Delete report record
        db.delete(report)
        db.commit()
        
        logger.info("Report deleted", report_id=report_id)
        
        return {"message": "Report deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete report", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete report")
