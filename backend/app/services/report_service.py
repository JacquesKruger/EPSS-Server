"""
Report Service - Generate various reports and analytics
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
import structlog
import os
import csv
import io
import pandas as pd

from app.core.database import get_db
from app.models.vulnerability import Vulnerability, Scan, VulnerabilityFinding
from app.services.vulnerability_service import vulnerability_service

logger = structlog.get_logger()


class ReportService:
    """Service for generating reports and analytics"""

    def __init__(self):
        self.vulnerability_service = vulnerability_service

    async def generate_report(
        self,
        report_type: str,
        format: str,
        scan_ids: Optional[List[int]] = None,
        filters: Optional[dict] = None,
    ) -> str:
        """Generate and persist a report file, returning its path."""
        db = next(get_db())
        try:
            rows = self._build_report_rows(db, scan_ids=scan_ids, filters=filters)
            output_dir = os.path.join("uploads", "reports")
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = "xlsx" if format == "excel" else format
            file_path = os.path.join(output_dir, f"{report_type}_report_{timestamp}.{ext}")

            if format == "csv":
                self._write_csv(file_path, rows)
            elif format == "excel":
                self._write_excel(file_path, rows)
            elif format == "pdf":
                self._write_simple_pdf(file_path, report_type, rows)
            else:
                raise ValueError(f"Unsupported report format: {format}")

            return file_path
        finally:
            db.close()

    def _build_report_rows(
        self,
        db: Session,
        scan_ids: Optional[List[int]] = None,
        filters: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        query = db.query(Vulnerability)

        if scan_ids:
            query = query.join(VulnerabilityFinding).filter(
                VulnerabilityFinding.scan_id.in_(scan_ids)
            )

        if filters:
            min_cpr = filters.get("min_cpr_score") if isinstance(filters, dict) else None
            risk_level = filters.get("risk_level") if isinstance(filters, dict) else None
            if min_cpr is not None:
                query = query.filter(Vulnerability.cpr_score >= float(min_cpr))
            if risk_level:
                query = query.filter(Vulnerability.cpr_risk_level == str(risk_level).lower())

        vulnerabilities = query.distinct().order_by(Vulnerability.cpr_score.desc().nulls_last()).all()

        counts = db.query(
            VulnerabilityFinding.vulnerability_id,
            func.count(VulnerabilityFinding.id).label("count"),
        )
        if scan_ids:
            counts = counts.filter(VulnerabilityFinding.scan_id.in_(scan_ids))
        findings_counts = counts.group_by(VulnerabilityFinding.vulnerability_id).all()
        findings_map = {v_id: count for v_id, count in findings_counts}

        return [
            {
                "CVE ID": vuln.cve_id,
                "Title": vuln.title or "",
                "Description": (vuln.description or "").replace("\n", " ").replace("\r", " "),
                "CVSS Score": vuln.cvss_score,
                "CVSS Severity": vuln.cvss_severity,
                "EPSS Score": vuln.epss_score,
                "EPSS Percentile": vuln.epss_percentile,
                "CPR Score": vuln.cpr_score,
                "CPR Risk Level": vuln.cpr_risk_level,
                "Findings": findings_map.get(vuln.id, 0),
                "Last Updated": vuln.updated_at.isoformat() if vuln.updated_at else "",
            }
            for vuln in vulnerabilities
        ]

    def _write_csv(self, file_path: str, rows: List[Dict[str, Any]]) -> None:
        headers = [
            "CVE ID",
            "Title",
            "Description",
            "CVSS Score",
            "CVSS Severity",
            "EPSS Score",
            "EPSS Percentile",
            "CPR Score",
            "CPR Risk Level",
            "Findings",
            "Last Updated",
        ]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    def _write_excel(self, file_path: str, rows: List[Dict[str, Any]]) -> None:
        df = pd.DataFrame(rows)
        df.to_excel(file_path, index=False)

    def _write_simple_pdf(self, file_path: str, report_type: str, rows: List[Dict[str, Any]]) -> None:
        """Write a minimal single-page PDF without external PDF libraries."""
        summary = [
            f"CPR Score Server - {report_type.title()} Report",
            f"Generated: {datetime.now().isoformat()}",
            f"Total vulnerabilities: {len(rows)}",
            "",
        ]
        for row in rows[:20]:
            summary.append(
                f"{row.get('CVE ID', '')} | CPR {row.get('CPR Score', '')} | {row.get('CPR Risk Level', '')}"
            )

        lines = []
        y = 760
        for text in summary:
            safe = str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            lines.append(f"BT /F1 10 Tf 50 {y} Td ({safe}) Tj ET")
            y -= 14

        content = "\n".join(lines)
        content_bytes = content.encode("latin-1", errors="replace")

        objects = []
        objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
        objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
        objects.append(
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
        )
        objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
        objects.append(
            f"5 0 obj << /Length {len(content_bytes)} >> stream\n".encode("ascii")
            + content_bytes
            + b"\nendstream endobj\n"
        )

        pdf = io.BytesIO()
        pdf.write(b"%PDF-1.4\n")
        offsets = [0]
        for obj in objects:
            offsets.append(pdf.tell())
            pdf.write(obj)

        xref_start = pdf.tell()
        pdf.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
        pdf.write(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.write(f"{offset:010d} 00000 n \n".encode("ascii"))
        pdf.write(
            f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
        )

        with open(file_path, "wb") as f:
            f.write(pdf.getvalue())

    async def generate_vulnerability_summary(
        self,
        db: Session,
        scan_id: Optional[int] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Generate vulnerability summary report"""
        try:
            query = db.query(Vulnerability)

            if scan_id:
                query = query.join(VulnerabilityFinding).filter(
                    VulnerabilityFinding.scan_id == scan_id
                )

            start_date = datetime.now() - timedelta(days=days)
            query = query.filter(Vulnerability.created_at >= start_date)

            total_vulns = query.count()
            critical_count = query.filter(Vulnerability.cvss_score >= 9.0).count()
            high_count = query.filter(
                and_(Vulnerability.cvss_score >= 7.0, Vulnerability.cvss_score < 9.0)
            ).count()
            medium_count = query.filter(
                and_(Vulnerability.cvss_score >= 4.0, Vulnerability.cvss_score < 7.0)
            ).count()
            low_count = query.filter(Vulnerability.cvss_score < 4.0).count()

            epss_stats = db.query(
                func.avg(Vulnerability.epss_score).label("avg_epss"),
                func.max(Vulnerability.epss_score).label("max_epss"),
                func.min(Vulnerability.epss_score).label("min_epss"),
            ).filter(Vulnerability.epss_score.isnot(None)).first()

            return {
                "total_vulnerabilities": total_vulns,
                "by_severity": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                },
                "epss_statistics": {
                    "average": float(epss_stats.avg_epss) if epss_stats.avg_epss else 0,
                    "maximum": float(epss_stats.max_epss) if epss_stats.max_epss else 0,
                    "minimum": float(epss_stats.min_epss) if epss_stats.min_epss else 0,
                },
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": datetime.now().isoformat(),
                    "days": days,
                },
            }

        except Exception as e:
            logger.error("Failed to generate vulnerability summary", error=str(e))
            raise

    async def generate_scan_report(self, db: Session, scan_id: int) -> Dict[str, Any]:
        """Generate detailed scan report"""
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan with ID {scan_id} not found")

            vulns = db.query(Vulnerability).join(VulnerabilityFinding).filter(
                VulnerabilityFinding.scan_id == scan_id
            ).all()

            vuln_data = []
            for vuln in vulns:
                cpr_score, risk_level = await self.vulnerability_service.epss_service.calculate_cpr_score(
                    vuln.cvss_score or 0,
                    vuln.epss_score or 0,
                )
                vuln_data.append(
                    {
                        "cve_id": vuln.cve_id,
                        "description": vuln.description,
                        "cvss_score": vuln.cvss_score,
                        "epss_score": vuln.epss_score,
                        "cpr_score": cpr_score,
                        "risk_level": risk_level,
                    }
                )

            vuln_data.sort(key=lambda x: x["cpr_score"] or 0, reverse=True)

            return {
                "scan": {
                    "id": scan.id,
                    "name": scan.name,
                    "type": scan.scan_type,
                    "created_at": scan.started_at.isoformat() if scan.started_at else None,
                    "status": scan.status,
                },
                "summary": {
                    "total_vulnerabilities": len(vuln_data),
                    "critical_risk": len([v for v in vuln_data if v["risk_level"] == "critical"]),
                    "high_risk": len([v for v in vuln_data if v["risk_level"] == "high"]),
                    "medium_risk": len([v for v in vuln_data if v["risk_level"] == "medium"]),
                    "low_risk": len([v for v in vuln_data if v["risk_level"] == "low"]),
                },
                "vulnerabilities": vuln_data,
            }

        except Exception as e:
            logger.error("Failed to generate scan report", error=str(e))
            raise

    async def generate_trend_analysis(self, db: Session, days: int = 90) -> Dict[str, Any]:
        """Generate vulnerability trend analysis"""
        try:
            start_date = datetime.now() - timedelta(days=days)

            daily_counts = db.query(
                func.date(Vulnerability.created_at).label("date"),
                func.count(Vulnerability.id).label("count"),
            ).filter(Vulnerability.created_at >= start_date).group_by(
                func.date(Vulnerability.created_at)
            ).order_by("date").all()

            severity_trends = {}
            for severity in ["critical", "high", "medium", "low"]:
                score_ranges = {
                    "critical": (9.0, 10.0),
                    "high": (7.0, 9.0),
                    "medium": (4.0, 7.0),
                    "low": (0.0, 4.0),
                }

                min_score, max_score = score_ranges[severity]
                counts = db.query(
                    func.date(Vulnerability.created_at).label("date"),
                    func.count(Vulnerability.id).label("count"),
                ).filter(
                    and_(
                        Vulnerability.created_at >= start_date,
                        Vulnerability.cvss_score >= min_score,
                        Vulnerability.cvss_score < max_score,
                    )
                ).group_by(func.date(Vulnerability.created_at)).order_by("date").all()

                severity_trends[severity] = [
                    {"date": str(count.date), "count": count.count}
                    for count in counts
                ]

            return {
                "period": {
                    "start": start_date.isoformat(),
                    "end": datetime.now().isoformat(),
                    "days": days,
                },
                "daily_counts": [
                    {"date": str(count.date), "count": count.count}
                    for count in daily_counts
                ],
                "severity_trends": severity_trends,
            }

        except Exception as e:
            logger.error("Failed to generate trend analysis", error=str(e))
            raise

    def _get_risk_level(self, cpr_score: float) -> str:
        """Determine risk level based on CPR score"""
        if cpr_score >= 90:
            return "critical"
        if cpr_score >= 70:
            return "high"
        if cpr_score >= 40:
            return "medium"
        return "low"


# Global service instance
report_service = ReportService()
