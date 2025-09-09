"""
EPSS (Exploit Prediction Scoring System) Service
"""

import httpx
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from app.core.config import settings

logger = structlog.get_logger()


class EPPSService:
    """Service for interacting with EPSS API"""
    
    def __init__(self):
        self.base_url = settings.EPSS_API_URL
        self.api_key = settings.EPSS_API_KEY
        self.cache = {}
        self.cache_ttl = timedelta(hours=1)
    
    async def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Retrieve EPSS scores for a list of CVE IDs
        
        Args:
            cve_ids: List of CVE identifiers
            
        Returns:
            Dictionary mapping CVE IDs to their EPSS data
        """
        if not cve_ids:
            return {}
        
        # Check cache first
        cached_results = {}
        uncached_cves = []
        
        for cve_id in cve_ids:
            if cve_id in self.cache:
                cache_entry = self.cache[cve_id]
                if datetime.now() - cache_entry['timestamp'] < self.cache_ttl:
                    cached_results[cve_id] = cache_entry['data']
                else:
                    uncached_cves.append(cve_id)
            else:
                uncached_cves.append(cve_id)
        
        # Fetch uncached CVEs
        if uncached_cves:
            fresh_results = await self._fetch_epss_scores(uncached_cves)
            
            # Update cache
            for cve_id, data in fresh_results.items():
                self.cache[cve_id] = {
                    'data': data,
                    'timestamp': datetime.now()
                }
            
            # Merge results
            cached_results.update(fresh_results)
        
        logger.info(
            "Retrieved EPSS scores",
            total_cves=len(cve_ids),
            cached=len(cached_results) - len(uncached_cves),
            fetched=len(uncached_cves)
        )
        
        return cached_results
    
    async def _fetch_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch EPSS scores from the API
        
        Args:
            cve_ids: List of CVE identifiers
            
        Returns:
            Dictionary mapping CVE IDs to their EPSS data
        """
        results = {}
        
        # EPSS API typically returns data for a date range
        # We'll fetch the latest available data
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get latest EPSS data
                params = {
                    'cve': ','.join(cve_ids),
                    'format': 'json'
                }
                
                if self.api_key:
                    params['key'] = self.api_key
                
                response = await client.get(f"{self.base_url}", params=params)
                response.raise_for_status()
                
                data = response.json()
                
                # Parse EPSS response
                if 'data' in data:
                    for item in data['data']:
                        cve_id = item.get('cve')
                        if cve_id:
                            results[cve_id] = {
                                'epss_score': float(item.get('epss', 0)),
                                'percentile': float(item.get('percentile', 0)),
                                'date': item.get('date'),
                                'status': 'success'
                            }
                
                # Handle CVEs not found in EPSS
                for cve_id in cve_ids:
                    if cve_id not in results:
                        results[cve_id] = {
                            'epss_score': 0.0,
                            'percentile': 0.0,
                            'date': None,
                            'status': 'not_found'
                        }
                
        except httpx.HTTPError as e:
            logger.error("EPSS API request failed", error=str(e))
            # Return default values for all CVEs
            for cve_id in cve_ids:
                results[cve_id] = {
                    'epss_score': 0.0,
                    'percentile': 0.0,
                    'date': None,
                    'status': 'error'
                }
        
        except Exception as e:
            logger.error("Unexpected error fetching EPSS scores", error=str(e))
            # Return default values for all CVEs
            for cve_id in cve_ids:
                results[cve_id] = {
                    'epss_score': 0.0,
                    'percentile': 0.0,
                    'date': None,
                    'status': 'error'
                }
        
        return results
    
    async def get_epss_percentile(self, epss_score: float) -> float:
        """
        Convert EPSS score to percentile
        
        Args:
            epss_score: Raw EPSS score (0-1)
            
        Returns:
            Percentile value (0-100)
        """
        # EPSS scores are already in percentile format
        # Just ensure they're in the correct range
        return min(100.0, max(0.0, epss_score * 100))
    
    async def get_cvss_percentile(self, cvss_score: float) -> float:
        """
        Convert CVSS score to percentile
        
        Args:
            cvss_score: CVSS score (0-10)
            
        Returns:
            Percentile value (0-100)
        """
        # CVSS scores range from 0-10, convert to 0-100 percentile
        return min(100.0, max(0.0, (cvss_score / 10.0) * 100))
    
    async def calculate_cpr_score(
        self, 
        cvss_score: float, 
        epss_score: float
    ) -> Tuple[float, str]:
        """
        Calculate CPR (Cybersecurity Priority Risk) score
        
        Args:
            cvss_score: CVSS score (0-10)
            epss_score: EPSS score (0-1)
            
        Returns:
            Tuple of (cpr_score, risk_level)
        """
        # Convert to percentiles
        cvss_percentile = await self.get_cvss_percentile(cvss_score)
        epss_percentile = await self.get_epss_percentile(epss_score)
        
        # Calculate weighted CPR score
        cpr_score = (
            cvss_percentile * settings.CVSS_WEIGHT + 
            epss_percentile * settings.EPSS_WEIGHT
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(cpr_score)
        
        return cpr_score, risk_level
    
    def _determine_risk_level(self, cpr_score: float) -> str:
        """
        Determine risk level based on CPR score
        
        Args:
            cpr_score: CPR score (0-100)
            
        Returns:
            Risk level string
        """
        thresholds = settings.CPR_THRESHOLDS
        
        if cpr_score >= thresholds['critical']:
            return 'critical'
        elif cpr_score >= thresholds['high']:
            return 'high'
        elif cpr_score >= thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    async def get_epss_statistics(self) -> Dict:
        """
        Get EPSS statistics for dashboard
        
        Returns:
            Dictionary with EPSS statistics
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {'format': 'json', 'stats': 'true'}
                if self.api_key:
                    params['key'] = self.api_key
                
                response = await client.get(f"{self.base_url}/stats", params=params)
                response.raise_for_status()
                
                return response.json()
                
        except Exception as e:
            logger.error("Failed to fetch EPSS statistics", error=str(e))
            return {}


# Global service instance
epss_service = EPPSService()
