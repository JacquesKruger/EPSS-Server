"""
File Upload Endpoints
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional
import structlog
from app.services.csv_processor import csv_processor
from app.services.vulnerability_service import vulnerability_service
from app.models.vulnerability import Scan
from app.core.database import get_db
from sqlalchemy.orm import Session

router = APIRouter()
logger = structlog.get_logger()


@router.post("/csv")
async def upload_csv(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_type: str = Form(...),
    scan_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Upload and process CSV file from vulnerability scanner
    
    Args:
        file: CSV file to upload
        scan_type: Type of scanner (wazuh, openvas)
        scan_name: Optional name for the scan
        
    Returns:
        Scan information and processing status
    """
    try:
        # Validate file type
        if not file.content_type in ['text/csv', 'application/vnd.ms-excel']:
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Please upload a CSV file."
            )
        
        # Validate scan type
        if scan_type.lower() not in ['wazuh', 'openvas']:
            raise HTTPException(
                status_code=400,
                detail="Invalid scan type. Supported types: wazuh, openvas"
            )
        
        # Read file content
        file_content = await file.read()
        
        # Validate CSV format
        if not csv_processor.validate_csv_format(file_content, scan_type):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid CSV format for {scan_type} scanner"
            )
        
        # Create scan record
        scan_name = scan_name or f"{scan_type}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan = Scan(
            name=scan_name,
            scan_type=scan_type.lower(),
            source_file=file.filename,
            status="processing"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Process file in background
        background_tasks.add_task(
            process_csv_file,
            scan.id,
            file_content,
            scan_type,
            scan_name
        )
        
        logger.info(
            "CSV upload initiated",
            scan_id=scan.id,
            scan_name=scan_name,
            scan_type=scan_type,
            filename=file.filename
        )
        
        return JSONResponse(
            status_code=202,
            content={
                "message": "File uploaded successfully. Processing in background.",
                "scan_id": scan.id,
                "scan_name": scan_name,
                "status": "processing"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("CSV upload failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to process CSV file"
        )


async def process_csv_file(scan_id: int, file_content: bytes, scan_type: str, scan_name: str):
    """
    Background task to process CSV file
    
    Args:
        scan_id: ID of the scan record
        file_content: Raw file content
        scan_type: Type of scanner
        scan_name: Name of the scan
    """
    try:
        # Process CSV
        processed_data = await csv_processor.process_csv(
            file_content, 
            scan_type, 
            scan_name
        )
        
        # Store vulnerability data
        await vulnerability_service.store_scan_data(scan_id, processed_data)
        
        logger.info(
            "CSV processing completed",
            scan_id=scan_id,
            total_findings=processed_data['total_findings'],
            unique_cves=len(processed_data['unique_cves'])
        )
        
    except Exception as e:
        logger.error(
            "CSV processing failed",
            scan_id=scan_id,
            error=str(e)
        )
        
        # Update scan status to failed
        db = next(get_db())
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                db.commit()
        finally:
            db.close()


@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """
    Get scan processing status
    
    Args:
        scan_id: ID of the scan
        
    Returns:
        Scan status information
    """
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan not found"
            )
        
        return {
            "scan_id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "total_findings": scan.total_findings,
            "unique_cves": scan.unique_cves,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error_message
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan status", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve scan status"
        )


@router.get("/scans")
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all scans with optional filtering
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        status: Filter by scan status
        
    Returns:
        List of scans
    """
    try:
        query = db.query(Scan)
        
        if status:
            query = query.filter(Scan.status == status)
        
        scans = query.offset(skip).limit(limit).all()
        
        return {
            "scans": [
                {
                    "scan_id": scan.id,
                    "name": scan.name,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "total_findings": scan.total_findings,
                    "unique_cves": scan.unique_cves,
                    "started_at": scan.started_at,
                    "completed_at": scan.completed_at
                }
                for scan in scans
            ],
            "total": query.count()
        }
        
    except Exception as e:
        logger.error("Failed to list scans", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve scans"
        )
