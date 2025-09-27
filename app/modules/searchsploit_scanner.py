"""
Searchsploit scanning module
Handles exploit database lookups using searchsploit
"""

import subprocess
import json
import re
from typing import Dict, List, Any, Optional
from app.models import Scan, Vulnerability, Port, db
from app.modules.logger import get_logger

logger = get_logger(__name__)

class SearchsploitScanner:
    """Searchsploit functionality for exploit database lookups"""
    
    def __init__(self):
        self.searchsploit_path = self._find_searchsploit()
    
    def _find_searchsploit(self) -> str:
        """Find searchsploit binary path"""
        try:
            # Try common locations
            common_paths = [
                'searchsploit',
                '/usr/bin/searchsploit',
                '/usr/local/bin/searchsploit',
                '/opt/exploitdb/searchsploit'
            ]
            
            for path in common_paths:
                try:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        logger.info(f"Found searchsploit at {path}")
                        return path
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            raise Exception("Searchsploit not found in common locations")
            
        except Exception as e:
            logger.warning(f"Searchsploit not available: {str(e)}")
            return None
    
    def search_exploits(self, service: str, version: str = None, cve: str = None) -> List[Dict[str, Any]]:
        """
        Search for exploits using searchsploit
        
        Args:
            service: Service name to search for
            version: Service version (optional)
            cve: CVE ID to search for (optional)
            
        Returns:
            List of exploit information
        """
        if not self.searchsploit_path:
            logger.warning("Searchsploit not available, skipping exploit search")
            return []
        
        try:
            exploits = []
            
            # Search by service name
            if service:
                exploits.extend(self._search_by_service(service, version))
            
            # Search by CVE
            if cve:
                exploits.extend(self._search_by_cve(cve))
            
            # Remove duplicates
            unique_exploits = []
            seen_ids = set()
            
            for exploit in exploits:
                exploit_id = exploit.get('id')
                if exploit_id and exploit_id not in seen_ids:
                    unique_exploits.append(exploit)
                    seen_ids.add(exploit_id)
            
            logger.info(f"Found {len(unique_exploits)} exploits for {service}")
            return unique_exploits
            
        except Exception as e:
            logger.error(f"Searchsploit search failed: {str(e)}")
            return []
    
    def _search_by_service(self, service: str, version: str = None) -> List[Dict[str, Any]]:
        """Search exploits by service name"""
        try:
            # Build search query
            query = service
            if version:
                query = f"{service} {version}"
            
            # Run searchsploit command
            cmd = [self.searchsploit_path, '--json', query]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.warning(f"Searchsploit search failed: {result.stderr}")
                return []
            
            # Parse JSON output
            try:
                data = json.loads(result.stdout)
                exploits = data.get('RESULTS_EXPLOIT', [])
                
                parsed_exploits = []
                for exploit in exploits:
                    parsed_exploit = self._parse_exploit_info(exploit)
                    if parsed_exploit:
                        parsed_exploits.append(parsed_exploit)
                
                return parsed_exploits
                
            except json.JSONDecodeError:
                # Fallback to text parsing if JSON fails
                return self._parse_text_output(result.stdout)
                
        except subprocess.TimeoutExpired:
            logger.warning("Searchsploit search timed out")
            return []
        except Exception as e:
            logger.error(f"Service search failed: {str(e)}")
            return []
    
    def _search_by_cve(self, cve: str) -> List[Dict[str, Any]]:
        """Search exploits by CVE ID"""
        try:
            cmd = [self.searchsploit_path, '--json', '--cve', cve]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return []
            
            try:
                data = json.loads(result.stdout)
                exploits = data.get('RESULTS_EXPLOIT', [])
                
                parsed_exploits = []
                for exploit in exploits:
                    parsed_exploit = self._parse_exploit_info(exploit)
                    if parsed_exploit:
                        parsed_exploits.append(parsed_exploit)
                
                return parsed_exploits
                
            except json.JSONDecodeError:
                return self._parse_text_output(result.stdout)
                
        except Exception as e:
            logger.error(f"CVE search failed: {str(e)}")
            return []
    
    def _parse_exploit_info(self, exploit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse exploit information from searchsploit JSON output"""
        try:
            return {
                'id': exploit.get('ID'),
                'title': exploit.get('Title', ''),
                'description': exploit.get('Description', ''),
                'author': exploit.get('Author', ''),
                'date': exploit.get('Date_Published', ''),
                'platform': exploit.get('Platform', ''),
                'type': exploit.get('Type', ''),
                'port': exploit.get('Port', ''),
                'path': exploit.get('Path', ''),
                'verified': exploit.get('Verified', False),
                'codes': exploit.get('Codes', ''),
                'tags': exploit.get('Tags', ''),
                'edb_id': exploit.get('EDB-ID', ''),
                'cve': self._extract_cve_from_title(exploit.get('Title', ''))
            }
        except Exception as e:
            logger.error(f"Failed to parse exploit info: {str(e)}")
            return None
    
    def _parse_text_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse searchsploit text output as fallback"""
        exploits = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    exploit = {
                        'id': parts[0].strip(),
                        'title': parts[1].strip(),
                        'path': parts[2].strip(),
                        'cve': self._extract_cve_from_title(parts[1].strip())
                    }
                    exploits.append(exploit)
        
        return exploits
    
    def _extract_cve_from_title(self, title: str) -> Optional[str]:
        """Extract CVE ID from exploit title"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, title, re.IGNORECASE)
        return match.group(0) if match else None
    
    def save_exploit_results(self, scan_id: int, port_id: int, exploits: List[Dict[str, Any]]) -> None:
        """Save exploit search results to database"""
        try:
            for exploit in exploits:
                # Create vulnerability record
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    port_id=port_id,
                    cve_id=exploit.get('cve'),
                    title=exploit.get('title', 'Exploit Available'),
                    description=exploit.get('description', ''),
                    severity=self._determine_exploit_severity(exploit),
                    exploit_available=True,
                    exploit_reference=exploit.get('path', ''),
                    remediation=self._generate_remediation(exploit)
                )
                db.session.add(vulnerability)
            
            db.session.commit()
            logger.info(f"Saved {len(exploits)} exploit results for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save exploit results: {str(e)}")
            raise
    
    def _determine_exploit_severity(self, exploit: Dict[str, Any]) -> str:
        """Determine severity based on exploit information"""
        title = exploit.get('title', '').lower()
        description = exploit.get('description', '').lower()
        
        # Check for high-severity keywords
        high_severity_keywords = ['remote code execution', 'rce', 'privilege escalation', 
                                'buffer overflow', 'sql injection', 'xss']
        
        if any(keyword in title or keyword in description for keyword in high_severity_keywords):
            return 'high'
        
        # Check for medium-severity keywords
        medium_severity_keywords = ['denial of service', 'dos', 'information disclosure', 
                                  'cross-site scripting', 'csrf']
        
        if any(keyword in title or keyword in description for keyword in medium_severity_keywords):
            return 'medium'
        
        return 'low'
    
    def _generate_remediation(self, exploit: Dict[str, Any]) -> str:
        """Generate remediation advice for exploit"""
        remediation = []
        
        if exploit.get('cve'):
            remediation.append(f"Apply security patches for {exploit['cve']}")
        
        if exploit.get('platform'):
            remediation.append(f"Update {exploit['platform']} to latest version")
        
        remediation.append("Review and implement security best practices")
        remediation.append("Consider implementing additional security controls")
        
        return "\n".join(remediation)
