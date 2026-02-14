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
        self.supported_formats = ['wazuh', 'openvas', 'manual']
    
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
            elif scan_type.lower() == 'manual':
                return await self._process_manual_csv(df, scan_name)
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
        - vulnerability.id, vulnerability, vulnerability.se, agent.name, package.name, package.version
        """
        try:
            # Standardize column names (case-insensitive)
            df.columns = df.columns.str.lower().str.strip()
            
            # Map Wazuh-specific column variations
            column_mapping = {
                'cve': ['vulnerability.id', 'vulnerability_id', 'cve', 'cve_id', 'cve-id'],
                'title': ['vulnerability', 'vulnerability.title', 'title', 'name', 'vulnerability_name'],
                'description': ['vulnerability', 'vulnerability.description', 'vulnerability.descr', 'vulnerability.desc', 'description', 'desc', 'details'],
                'severity': ['vulnerability.severity', 'vulnerability.se', 'vulnerability_severity', 'severity', 'level', 'risk'],
                'hostname': ['agent.name', 'agent_name', 'hostname', 'host', 'host_name', 'computer_name'],
                'package_name': ['package.name', 'package_name', 'package'],
                'package_version': ['package.version', 'package_version', 'version'],
                'cvss': ['cvss', 'cvss_score', 'cvss-score', 'score'],
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
            required_columns = ['cve', 'hostname']
            missing_columns = [col for col in required_columns if col not in actual_columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Extract unique CVEs
            unique_cves = df[actual_columns['cve']].dropna().unique().tolist()
            
            # Process findings
            findings = []
            for _, row in df.iterrows():
                # Normalize severity and map to CVSS-like scores
                raw_severity = str(row.get(actual_columns.get('severity', ''), '')).strip().lower()
                cvss_from_column = None
                if 'cvss' in actual_columns:
                    cvss_from_column = self._safe_float(row.get(actual_columns['cvss']))
                
                cvss_score = None
                normalized_severity = None
                
                # Prefer explicit CVSS column if present
                if cvss_from_column is not None:
                    cvss_score = cvss_from_column
                    if cvss_score >= 9.0:
                        normalized_severity = 'critical'
                    elif cvss_score >= 7.0:
                        normalized_severity = 'high'
                    elif cvss_score >= 4.0:
                        normalized_severity = 'medium'
                    else:
                        normalized_severity = 'low'
                else:
                    # Map textual or numeric severities
                    if raw_severity in ['critical', 'high', 'medium', 'low']:
                        normalized_severity = raw_severity
                        if raw_severity == 'critical':
                            cvss_score = 9.0
                        elif raw_severity == 'high':
                            cvss_score = 8.0
                        elif raw_severity == 'medium':
                            cvss_score = 5.0
                        elif raw_severity == 'low':
                            cvss_score = 2.0
                    else:
                        # If numeric (e.g., '10', '7', etc.), convert to buckets
                        try:
                            sev_num = float(raw_severity)
                            if sev_num >= 9.0:
                                normalized_severity = 'critical'
                                cvss_score = 9.0
                            elif sev_num >= 7.0:
                                normalized_severity = 'high'
                                cvss_score = 8.0
                            elif sev_num >= 4.0:
                                normalized_severity = 'medium'
                                cvss_score = 5.0
                            elif sev_num > 0:
                                normalized_severity = 'low'
                                cvss_score = 2.0
                        except Exception:
                            normalized_severity = None
                
                finding = {
                    'cve_id': str(row[actual_columns['cve']]).strip(),
                    'ip_address': str(row[actual_columns['hostname']]).strip(),  # Use hostname as IP for Wazuh
                    'hostname': str(row[actual_columns['hostname']]).strip(),
                    'port': self._safe_int(row.get(actual_columns.get('port', ''))),
                    'protocol': str(row.get(actual_columns.get('protocol', ''), '')).strip() or None,
                    'service': str(row.get(actual_columns.get('service', ''), '')).strip() or None,
                    'title': (str(row.get(actual_columns.get('title', ''), '')).strip() or str(row.get(actual_columns.get('description', ''), '')).strip() or None),
                    'description': str(row.get(actual_columns.get('description', ''), '')).strip() or None,
                    'cvss_score': cvss_score,
                    'severity': normalized_severity or (raw_severity if raw_severity else 'unknown')
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
        - NVT Name, CVEs, Summary, CVSS, Severity, IP, Hostname, Port, Port Protocol
        """
        try:
            # Standardize column names
            df.columns = df.columns.str.lower().str.strip()
            
            # Map OpenVAS column variations
            column_mapping = {
                'cve': ['cves', 'cve', 'cve_id', 'cve-id', 'nvt_cve'],
                'nvt_name': ['nvt name', 'nvt_name', 'name', 'title', 'vulnerability_name'],
                'title': ['nvt name', 'nvt_name', 'name', 'title', 'vulnerability_name'],
                'description': ['summary', 'description', 'desc', 'specific_result', 'specific result'],
                'cvss': ['cvss', 'cvss_score', 'cvss-score', 'score'],
                'severity': ['severity', 'level', 'risk', 'threat'],
                'ip': ['ip', 'host', 'ip_address', 'host_ip', 'hostname'],
                'port': ['port', 'port_number'],
                'protocol': ['port protocol', 'port_protocol', 'protocol', 'proto'],
                'service': ['service', 'service_name', 'affected_software', 'affected software']
            }
            
            # Find actual column names
            actual_columns = {}
            for standard_name, variations in column_mapping.items():
                for variation in variations:
                    if variation in df.columns:
                        actual_columns[standard_name] = variation
                        break
            
            # Validate required columns
            required_columns = ['nvt_name', 'ip']
            missing_columns = [col for col in required_columns if col not in actual_columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Process findings and extract CVEs
            findings = []
            unique_cves = set()
            
            for _, row in df.iterrows():
                # Get NVT name and try to extract CVE from it or CVEs column
                nvt_name = str(row[actual_columns['nvt_name']]).strip()
                cve_id = self._extract_cve_from_openvas(row, actual_columns, nvt_name)
                
                if cve_id:
                    unique_cves.add(cve_id)
                
                finding = {
                    'cve_id': cve_id or f"NVT-{hash(nvt_name) % 100000}",  # Fallback ID if no CVE
                    'ip_address': str(row[actual_columns['ip']]).strip(),
                    'hostname': str(row.get(actual_columns.get('hostname', ''), '')).strip() or None,
                    'port': self._safe_int(row.get(actual_columns.get('port', ''))),
                    'protocol': str(row.get(actual_columns.get('protocol', ''), '')).strip() or None,
                    'service': str(row.get(actual_columns.get('service', ''), '')).strip() or None,
                    'title': nvt_name,  # Use NVT name as title
                    'description': str(row.get(actual_columns.get('description', ''), '')).strip() or None,
                    'cvss_score': self._safe_float(row.get(actual_columns.get('cvss', ''))),
                    'severity': str(row.get(actual_columns.get('severity', ''), '')).strip() or None
                }
                findings.append(finding)
            
            return {
                'scan_name': scan_name,
                'scan_type': 'openvas',
                'total_findings': len(findings),
                'unique_cves': list(unique_cves),
                'findings': findings,
                'processed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to process OpenVAS CSV", error=str(e))
            raise
    
    def _extract_cve_from_openvas(self, row, actual_columns, nvt_name):
        """
        Extract CVE ID from OpenVAS data
        
        Args:
            row: DataFrame row
            actual_columns: Mapped column names
            nvt_name: NVT name from the row
            
        Returns:
            CVE ID if found, None otherwise
        """
        import re
        
        # First try to get CVE from CVEs column if it exists
        if 'cve' in actual_columns:
            cve_value = str(row[actual_columns['cve']]).strip()
            if cve_value and cve_value != 'nan' and cve_value != 'None':
                # Look for CVE pattern in the CVEs column
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', cve_value)
                if cve_match:
                    return cve_match.group(0)
        
        # Try to extract CVE from NVT name
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', nvt_name)
        if cve_match:
            return cve_match.group(0)
        
        # Try to extract from description/summary if available
        if 'description' in actual_columns:
            desc_value = str(row[actual_columns['description']]).strip()
            if desc_value and desc_value != 'nan' and desc_value != 'None':
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', desc_value)
                if cve_match:
                    return cve_match.group(0)
        
        return None

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
                required_columns = ['cve', 'hostname']  # Wazuh uses hostname instead of IP
            elif scan_type.lower() == 'openvas':
                required_columns = ['nvt_name', 'ip']  # OpenVAS uses NVT Name instead of CVE
            elif scan_type.lower() == 'manual':
                required_columns = ['cve', 'title', 'cvss', 'severity']
            else:
                return False
            
            # Check if any required column exists (case-insensitive)
            df.columns = df.columns.str.lower().str.strip()
            
            # For Wazuh, check for specific column patterns
            if scan_type.lower() == 'wazuh':
                has_cve = any('vulnerability.id' in col or 'cve' in col for col in df.columns)
                has_hostname = any('agent.name' in col or 'hostname' in col for col in df.columns)
                has_required = has_cve and has_hostname
            else:
                # For non-Wazuh formats we require every expected logical column.
                has_required = all(
                    any(req_col in col for col in df.columns)
                    for req_col in required_columns
                )
            
            return has_required and len(df) > 0
            
        except Exception as e:
            logger.error("CSV validation failed", error=str(e))
            return False
    
    async def _process_manual_csv(self, df: pd.DataFrame, scan_name: str) -> Dict:
        """
        Process manual CSV format with standard vulnerability columns
        
        Expected columns:
        - CVE ID, Title, CVSS Score, Severity, Description, IP Address, Port, Service
        """
        try:
            # Normalize column names
            df.columns = df.columns.str.lower().str.strip()
            
            # Map common column variations
            column_mapping = {
                'cve_id': ['cve id', 'cve-id', 'cve', 'cve_id'],
                'title': ['title', 'name', 'vulnerability'],
                'cvss_score': ['cvss score', 'cvss', 'score', 'cvss_score'],
                'severity': ['severity', 'level', 'risk'],
                'description': ['description', 'desc', 'details'],
                'ip_address': ['ip address', 'ip', 'host', 'ip_address'],
                'port': ['port', 'port number'],
                'service': ['service', 'protocol', 'app']
            }
            
            # Find matching columns
            mapped_columns = {}
            for target_col, variations in column_mapping.items():
                for col in df.columns:
                    if any(var in col for var in variations):
                        mapped_columns[target_col] = col
                        break
            
            # Validate required columns
            required = ['cve_id', 'title', 'cvss_score', 'severity']
            missing = [col for col in required if col not in mapped_columns]
            if missing:
                raise ValueError(f"Missing required columns: {missing}")
            
            # Process vulnerabilities
            vulnerabilities = []
            for _, row in df.iterrows():
                vuln_data = {
                    'cve_id': str(row.get(mapped_columns.get('cve_id', ''), '')).strip(),
                    'title': str(row.get(mapped_columns.get('title', ''), '')).strip(),
                    'cvss_score': self._safe_float(row.get(mapped_columns.get('cvss_score', ''), 0)),
                    'severity': str(row.get(mapped_columns.get('severity', ''), '')).strip().lower(),
                    'description': str(row.get(mapped_columns.get('description', ''), '')).strip(),
                    'ip_address': str(row.get(mapped_columns.get('ip_address', ''), '')).strip(),
                    'port': self._safe_int(row.get(mapped_columns.get('port', ''), None)),
                    'service': str(row.get(mapped_columns.get('service', ''), '')).strip()
                }
                
                # Skip empty CVE IDs
                if vuln_data['cve_id'] and vuln_data['cve_id'] != 'nan':
                    vulnerabilities.append(vuln_data)
            
            # Calculate statistics
            total_findings = len(vulnerabilities)
            unique_cves = list(set(v['cve_id'] for v in vulnerabilities if v['cve_id']))
            
            severity_counts = {
                'critical': len([v for v in vulnerabilities if v['severity'] in ['critical', '9', '10']]),
                'high': len([v for v in vulnerabilities if v['severity'] in ['high', '7', '8']]),
                'medium': len([v for v in vulnerabilities if v['severity'] in ['medium', '4', '5', '6']]),
                'low': len([v for v in vulnerabilities if v['severity'] in ['low', '1', '2', '3']])
            }
            
            return {
                'scan_name': scan_name,
                'scan_type': 'manual',
                'total_findings': total_findings,
                'unique_cves': unique_cves,  # List of CVE IDs
                'unique_cves_count': len(unique_cves),  # Count for statistics
                'severity_counts': severity_counts,
                'findings': vulnerabilities,  # Use 'findings' to match expected format
                'processed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to process manual CSV", error=str(e))
            raise
    
    def _safe_float(self, value) -> Optional[float]:
        """Safely convert value to float"""
        try:
            if pd.isna(value) or value == '' or value is None:
                return None
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def _safe_int(self, value) -> Optional[int]:
        """Safely convert value to int"""
        try:
            if pd.isna(value) or value == '' or value is None:
                return None
            return int(float(value))
        except (ValueError, TypeError):
            return None


# Global service instance
csv_processor = CSVProcessor()
