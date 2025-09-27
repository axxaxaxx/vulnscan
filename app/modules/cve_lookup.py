"""
CVE lookup module
Handles CVE database lookups and vulnerability information retrieval
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from typing import Dict, List, Any, Optional
from app.models import Scan, Vulnerability, Port, db
from app.modules.logger import get_logger

logger = get_logger(__name__)

class CVELookup:
    """CVE database lookup functionality"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnScanner/1.0 (Security Research Tool)'
        })
        
        # CVE data sources
        self.cve_sources = {
            'nvd': 'https://nvd.nist.gov/vuln/detail/',
            'cve_mitre': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=',
            'cve_details': 'https://www.cvedetails.com/cve/'
        }
    
    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Look up CVE information from multiple sources
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-1234)
            
        Returns:
            Dictionary containing CVE information
        """
        try:
            logger.info(f"Looking up CVE: {cve_id}")
            
            # Try NVD first (most reliable)
            cve_data = self._lookup_nvd(cve_id)
            if cve_data:
                return cve_data
            
            # Fallback to CVE Details
            cve_data = self._lookup_cve_details(cve_id)
            if cve_data:
                return cve_data
            
            # Last resort: MITRE CVE
            cve_data = self._lookup_mitre_cve(cve_id)
            return cve_data
            
        except Exception as e:
            logger.error(f"CVE lookup failed for {cve_id}: {str(e)}")
            return None
    
    def _lookup_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up CVE from NVD (National Vulnerability Database)"""
        try:
            url = f"{self.cve_sources['nvd']}{cve_id}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract CVE information
            cve_data = {
                'cve_id': cve_id,
                'source': 'NVD',
                'url': url
            }
            
            # Get CVE description
            desc_element = soup.find('p', {'data-testid': 'vuln-description'})
            if desc_element:
                cve_data['description'] = desc_element.get_text().strip()
            
            # Get CVSS score
            cvss_element = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
            if cvss_element:
                try:
                    cve_data['cvss_score'] = float(cvss_element.get_text().strip())
                except ValueError:
                    pass
            
            # Get CVSS vector
            vector_element = soup.find('span', {'data-testid': 'vuln-cvss3-panel-vector'})
            if vector_element:
                cve_data['cvss_vector'] = vector_element.get_text().strip()
            
            # Get severity
            severity_element = soup.find('span', {'data-testid': 'vuln-cvss3-panel-severity'})
            if severity_element:
                cve_data['severity'] = severity_element.get_text().strip().lower()
            
            # Get published date
            published_element = soup.find('span', {'data-testid': 'vuln-published-on'})
            if published_element:
                cve_data['published_date'] = published_element.get_text().strip()
            
            # Get references
            references = []
            ref_elements = soup.find_all('a', {'data-testid': 'vuln-hyperlinks-link'})
            for ref in ref_elements:
                references.append({
                    'url': ref.get('href'),
                    'text': ref.get_text().strip()
                })
            cve_data['references'] = references
            
            logger.info(f"Successfully retrieved CVE data from NVD for {cve_id}")
            return cve_data
            
        except Exception as e:
            logger.warning(f"NVD lookup failed for {cve_id}: {str(e)}")
            return None
    
    def _lookup_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up CVE from CVE Details"""
        try:
            url = f"{self.cve_sources['cve_details']}{cve_id}/"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            cve_data = {
                'cve_id': cve_id,
                'source': 'CVE Details',
                'url': url
            }
            
            # Get description
            desc_element = soup.find('div', class_='cvedetailssummary')
            if desc_element:
                cve_data['description'] = desc_element.get_text().strip()
            
            # Get CVSS score
            score_element = soup.find('div', class_='cvssbox')
            if score_element:
                try:
                    score_text = score_element.get_text().strip()
                    score_match = re.search(r'(\d+\.?\d*)', score_text)
                    if score_match:
                        cve_data['cvss_score'] = float(score_match.group(1))
                except ValueError:
                    pass
            
            # Get severity
            severity_element = soup.find('span', class_='severity')
            if severity_element:
                cve_data['severity'] = severity_element.get_text().strip().lower()
            
            # Get published date
            published_element = soup.find('td', string=re.compile(r'\d{4}-\d{2}-\d{2}'))
            if published_element:
                cve_data['published_date'] = published_element.get_text().strip()
            
            logger.info(f"Successfully retrieved CVE data from CVE Details for {cve_id}")
            return cve_data
            
        except Exception as e:
            logger.warning(f"CVE Details lookup failed for {cve_id}: {str(e)}")
            return None
    
    def _lookup_mitre_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up CVE from MITRE CVE database"""
        try:
            url = f"{self.cve_sources['cve_mitre']}{cve_id}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            cve_data = {
                'cve_id': cve_id,
                'source': 'MITRE CVE',
                'url': url
            }
            
            # Get description
            desc_element = soup.find('td', string=re.compile(r'.*'))
            if desc_element:
                cve_data['description'] = desc_element.get_text().strip()
            
            logger.info(f"Successfully retrieved CVE data from MITRE for {cve_id}")
            return cve_data
            
        except Exception as e:
            logger.warning(f"MITRE CVE lookup failed for {cve_id}: {str(e)}")
            return None
    
    def search_cves_by_service(self, service: str, version: str = None) -> List[Dict[str, Any]]:
        """
        Search for CVEs related to a specific service and version
        
        Args:
            service: Service name
            version: Service version (optional)
            
        Returns:
            List of CVE information
        """
        try:
            logger.info(f"Searching CVEs for service: {service}, version: {version}")
            
            # Use NVD API for service-based search
            cves = self._search_nvd_api(service, version)
            
            # Enrich with detailed information
            enriched_cves = []
            for cve in cves:
                detailed_cve = self.lookup_cve(cve['cve_id'])
                if detailed_cve:
                    enriched_cves.append(detailed_cve)
            
            logger.info(f"Found {len(enriched_cves)} CVEs for {service}")
            return enriched_cves
            
        except Exception as e:
            logger.error(f"CVE search failed for {service}: {str(e)}")
            return []
    
    def _search_nvd_api(self, service: str, version: str = None) -> List[Dict[str, Any]]:
        """Search NVD API for CVEs related to service"""
        try:
            # Build search query
            query = f'"{service}"'
            if version:
                query += f' "{version}"'
            
            # NVD API endpoint
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': query,
                'resultsPerPage': 50
            }
            
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                cve_id = cve.get('id')
                
                if cve_id:
                    cves.append({
                        'cve_id': cve_id,
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'published_date': cve.get('published', ''),
                        'last_modified': cve.get('lastModified', '')
                    })
            
            return cves
            
        except Exception as e:
            logger.warning(f"NVD API search failed: {str(e)}")
            return []
    
    def save_cve_results(self, scan_id: int, port_id: int, cve_data: Dict[str, Any]) -> None:
        """Save CVE lookup results to database"""
        try:
            vulnerability = Vulnerability(
                scan_id=scan_id,
                port_id=port_id,
                cve_id=cve_data.get('cve_id'),
                title=f"CVE-{cve_data.get('cve_id', 'Unknown')}",
                description=cve_data.get('description', ''),
                severity=cve_data.get('severity', 'unknown'),
                cvss_score=cve_data.get('cvss_score'),
                cvss_vector=cve_data.get('cvss_vector'),
                remediation=self._generate_cve_remediation(cve_data)
            )
            
            db.session.add(vulnerability)
            db.session.commit()
            
            logger.info(f"Saved CVE {cve_data.get('cve_id')} for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save CVE results: {str(e)}")
            raise
    
    def _generate_cve_remediation(self, cve_data: Dict[str, Any]) -> str:
        """Generate remediation advice for CVE"""
        remediation = []
        
        cve_id = cve_data.get('cve_id')
        if cve_id:
            remediation.append(f"Apply security patches for {cve_id}")
        
        severity = cve_data.get('severity', '').lower()
        if severity in ['critical', 'high']:
            remediation.append("Priority: Address immediately")
        elif severity == 'medium':
            remediation.append("Priority: Address within 30 days")
        else:
            remediation.append("Priority: Address when possible")
        
        remediation.append("Monitor for vendor security advisories")
        remediation.append("Implement additional security controls if needed")
        
        return "\n".join(remediation)
