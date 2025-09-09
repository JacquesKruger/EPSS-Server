"""
CSV Processing Service for Wazuh and OpenVAS data
"""

import pandas as pd
import csv
import io
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import structlog
from app.core.config import settings

logger = structlog.get_logger()


class CSVProcessor:
    """Service for processing CSV files from different vulnerability scanners"""
    
    def __init__(self):
        self.supported_formats = ['wazuh', 'openvas']
    
    async def process_csv(
        self, 
        file_content: bytes, 
        scan_type: str,
        scan_name: str
    ) -> Dict:
        """
        Process CSV file and extract vulnerability data
        
        Args:
            file_content: Raw CSV file content
            scan_type: Type of scan (wazuh, openvas)
            scan_name: Name for the scan
            
        Returns:
            Dictionary with processed data
        """
        try:
            # Detect encoding
            encoding = self._detect_encoding(file_content)
            
            # Parse CSV
            df = pd.read_csv(io.BytesIO(file_content), encoding=encoding)
            
            # Process based on scan type
            if scan_type.lower() == 'wazuh':
                return await self._process_wazuh_csv(df, scan_name)
            elif scan_type.lower() == 'openvas':
                return await self._process_openvas_csv(df, scan_name)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
                
        except Exception as e:
            logger.error("Failed to process CSV file", error=str(e), scan_type=scan_type)
            raise
    
    def _detect_encoding(self, content: bytes) -> str:
        """Detect file encoding"""
        import chardet
        result = chardet.detect(content)
        return result.get('encoding', 'utf-8')
    
    async def _process_wazuh_csv(self, df: pd.DataFrame, scan_name: str) -> Dict:
        """
        Process Wazuh CSV format
        
        Expected Wazuh columns:
        - CVE, Title, Description, CVSS, Severity, IP, Hostname, Port, Protocol
        """
        try:
            # Standardize column names (case-insensitive)
            df.columns = df.columns.str.lower().str.strip()
            
            # Map common Wazuh column variations
            column_mapping = {
                'cve': ['cve', 'cve_id', 'cve-id', 'vulnerability_id'],
                'title': ['title', 'name', 'vulnerability_name'],
                'description': ['description', 'desc', 'details'],
                'cvss': ['cvss', 'cvss_score', 'cvss-score', 'score'],
                'severity': ['severity', 'level', 'risk'],
                'ip': ['ip', 'ip_address', 'ip-address', 'host_ip'],
                'hostname': ['hostname', 'host', 'host_name', 'computer_name'],
                'port': ['port', 'port_number'],
                'protocol': ['protocol', 'proto'],
                'service': ['service', 'service_name']
            }
            
            # Find actual column names
            actual_columns = {}
            for standard_name, variations in column_mapping.items():
                for variation in variations:
                    if variation in df.columns:
                        actual_columns[standard_name] = variation
                        break
            
            # Validate required columns
            required_columns = ['cve', 'ip']
            missing_columns = [col for col in required_columns if col not in actual_columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Extract unique CVEs
            unique_cves = df[actual_columns['cve']].dropna().unique().tolist()
            
            # Process findings
            findings = []
            for _, row in df.iterrows():
                finding = {
                    'cve_id': str(row[actual_columns['cve']]).strip(),
                    'ip_address': str(row[actual_columns['ip']]).strip(),
                    'hostname': str(row.get(actual_columns.get('hostname', ''), '')).strip() or None,
                    'port': self._safe_int(row.get(actual_columns.get('port', ''))),
                    'protocol': str(row.get(actual_columns.get('protocol', ''), '')).strip() or None,
                    'service': str(row.get(actual_columns.get('service', ''), '')).strip() or None,
                    'title': str(row.get(actual_columns.get('title', ''), '')).strip() or None,
                    'description': str(row.get(actual_columns.get('description', ''), '')).strip() or None,
                    'cvss_score': self._safe_float(row.get(actual_columns.get('cvss', ''))),
                    'severity': str(row.get(actual_columns.get('severity', ''), '')).strip() or None
                }
                findings.append(finding)
            
            return {
                'scan_name': scan_name,
                'scan_type': 'wazuh',
                'total_findings': len(findings),
                'unique_cves': unique_cves,
                'findings': findings,
                'processed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to process Wazuh CSV", error=str(e))
            raise
    
    async def _process_openvas_csv(self, df: pd.DataFrame, scan_name: str) -> Dict:
        """
        Process OpenVAS CSV format
        
        Expected OpenVAS columns:
        - CVE, Name, Description, CVSS, Severity, Host, Port, Protocol
        """
        try:
            # Standardize column names
            df.columns = df.columns.str.lower().str.strip()
            
            # Map OpenVAS column variations
            column_mapping = {
                'cve': ['cve', 'cve_id', 'cve-id', 'nvt_cve'],
                'title': ['name', 'title', 'nvt_name', 'vulnerability_name'],
                'description': ['description', 'desc', 'summary'],
                'cvss': ['cvss', 'cvss_score', 'cvss-score', 'score', 'qod'],
                'severity': ['severity', 'level', 'risk', 'threat'],
                'ip': ['host', 'ip', 'ip_address', 'host_ip', 'hostname'],
                'port': ['port', 'port_number'],
                'protocol': ['protocol', 'proto'],
                'service': ['service', 'service_name']
            }
            
            # Find actual column names
            actual_columns = {}
            for standard_name, variations in column_mapping.items():
                for variation in variations:
                    if variation in df.columns:
                        actual_columns[standard_name] = variation
                        break
            
            # Validate required columns
            required_columns = ['cve', 'ip']
            missing_columns = [col for col in required_columns if col not in actual_columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Extract unique CVEs
            unique_cves = df[actual_columns['cve']].dropna().unique().tolist()
            
            # Process findings
            findings = []
            for _, row in df.iterrows():
                finding = {
                    'cve_id': str(row[actual_columns['cve']]).strip(),
                    'ip_address': str(row[actual_columns['ip']]).strip(),
                    'hostname': str(row.get(actual_columns.get('hostname', ''), '')).strip() or None,
                    'port': self._safe_int(row.get(actual_columns.get('port', ''))),
                    'protocol': str(row.get(actual_columns.get('protocol', ''), '')).strip() or None,
                    'service': str(row.get(actual_columns.get('service', ''), '')).strip() or None,
                    'title': str(row.get(actual_columns.get('title', ''), '')).strip() or None,
                    'description': str(row.get(actual_columns.get('description', ''), '')).strip() or None,
                    'cvss_score': self._safe_float(row.get(actual_columns.get('cvss', ''))),
                    'severity': str(row.get(actual_columns.get('severity', ''), '')).strip() or None
                }
                findings.append(finding)
            
            return {
                'scan_name': scan_name,
                'scan_type': 'openvas',
                'total_findings': len(findings),
                'unique_cves': unique_cves,
                'findings': findings,
                'processed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to process OpenVAS CSV", error=str(e))
            raise
    
    def _safe_int(self, value) -> Optional[int]:
        """Safely convert value to integer"""
        if pd.isna(value) or value == '':
            return None
        try:
            return int(float(str(value)))
        except (ValueError, TypeError):
            return None
    
    def _safe_float(self, value) -> Optional[float]:
        """Safely convert value to float"""
        if pd.isna(value) or value == '':
            return None
        try:
            return float(str(value))
        except (ValueError, TypeError):
            return None
    
    def validate_csv_format(self, file_content: bytes, scan_type: str) -> bool:
        """
        Validate if CSV file matches expected format
        
        Args:
            file_content: Raw CSV file content
            scan_type: Expected scan type
            
        Returns:
            True if format is valid
        """
        try:
            encoding = self._detect_encoding(file_content)
            df = pd.read_csv(io.BytesIO(file_content), encoding=encoding, nrows=5)
            
            # Check for required columns based on scan type
            if scan_type.lower() == 'wazuh':
                required_columns = ['cve', 'ip']
            elif scan_type.lower() == 'openvas':
                required_columns = ['cve', 'host']
            else:
                return False
            
            # Check if any required column exists (case-insensitive)
            df.columns = df.columns.str.lower().str.strip()
            has_required = any(
                any(req_col in col for col in df.columns) 
                for req_col in required_columns
            )
            
            return has_required and len(df) > 0
            
        except Exception as e:
            logger.error("CSV validation failed", error=str(e))
            return False


# Global service instance
csv_processor = CSVProcessor()
