"""
OSINT (Open Source Intelligence) scanning module
Handles web scraping and OSINT data collection
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from app.models import Scan, db
from app.modules.logger import get_logger

logger = get_logger(__name__)

class OSINTScanner:
    """OSINT data collection functionality"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # OSINT sources
        self.osint_sources = {
            'shodan': 'https://www.shodan.io/host/',
            'censys': 'https://censys.io/ipv4/',
            'virustotal': 'https://www.virustotal.com/gui/ip-address/',
            'abuseipdb': 'https://www.abuseipdb.com/check/',
            'threatcrowd': 'https://www.threatcrowd.org/ip.php?ip=',
            'otx': 'https://otx.alienvault.com/indicator/ip/'
        }
    
    def collect_osint_data(self, target: str, scan_id: int) -> Dict[str, Any]:
        """
        Collect OSINT data for target
        
        Args:
            target: IP address or hostname
            scan_id: Scan ID for database reference
            
        Returns:
            Dictionary containing OSINT data
        """
        try:
            logger.info(f"Starting OSINT collection for {target}")
            
            osint_data = {
                'target': target,
                'scan_id': scan_id,
                'shodan_data': self._collect_shodan_data(target),
                'virustotal_data': self._collect_virustotal_data(target),
                'abuseipdb_data': self._collect_abuseipdb_data(target),
                'threatcrowd_data': self._collect_threatcrowd_data(target),
                'otx_data': self._collect_otx_data(target),
                'whois_data': self._collect_whois_data(target),
                'dns_data': self._collect_dns_data(target)
            }
            
            # Save to database
            self._save_osint_data(scan_id, osint_data)
            
            logger.info(f"OSINT collection completed for {target}")
            return osint_data
            
        except Exception as e:
            logger.error(f"OSINT collection failed for {target}: {str(e)}")
            return {}
    
    def _collect_shodan_data(self, target: str) -> Dict[str, Any]:
        """Collect data from Shodan (public information only)"""
        try:
            # Note: This is a simplified version that scrapes public Shodan data
            # For production use, you would need a Shodan API key
            url = f"{self.osint_sources['shodan']}{target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                data = {
                    'url': url,
                    'accessible': True,
                    'title': soup.title.string if soup.title else 'Unknown',
                    'ports': self._extract_shodan_ports(soup),
                    'services': self._extract_shodan_services(soup),
                    'location': self._extract_shodan_location(soup)
                }
                
                return data
            else:
                return {'url': url, 'accessible': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.warning(f"Shodan data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_shodan_ports(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract port information from Shodan page"""
        ports = []
        try:
            port_elements = soup.find_all('div', class_='port')
            for port_elem in port_elements:
                port_text = port_elem.get_text().strip()
                if port_text.isdigit():
                    ports.append({
                        'port': int(port_text),
                        'protocol': 'tcp'  # Default assumption
                    })
        except Exception:
            pass
        return ports
    
    def _extract_shodan_services(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract service information from Shodan page"""
        services = []
        try:
            service_elements = soup.find_all('div', class_='service')
            for service_elem in service_elements:
                service_text = service_elem.get_text().strip()
                if service_text:
                    services.append({'name': service_text})
        except Exception:
            pass
        return services
    
    def _extract_shodan_location(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract location information from Shodan page"""
        location = {}
        try:
            location_elem = soup.find('div', class_='location')
            if location_elem:
                location_text = location_elem.get_text().strip()
                location['raw'] = location_text
        except Exception:
            pass
        return location
    
    def _collect_virustotal_data(self, target: str) -> Dict[str, Any]:
        """Collect data from VirusTotal"""
        try:
            url = f"{self.osint_sources['virustotal']}{target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                data = {
                    'url': url,
                    'accessible': True,
                    'reputation': self._extract_vt_reputation(soup),
                    'detections': self._extract_vt_detections(soup),
                    'last_analysis': self._extract_vt_last_analysis(soup)
                }
                
                return data
            else:
                return {'url': url, 'accessible': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.warning(f"VirusTotal data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_vt_reputation(self, soup: BeautifulSoup) -> str:
        """Extract reputation score from VirusTotal"""
        try:
            reputation_elem = soup.find('span', class_='reputation')
            if reputation_elem:
                return reputation_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _extract_vt_detections(self, soup: BeautifulSoup) -> int:
        """Extract number of detections from VirusTotal"""
        try:
            detection_elem = soup.find('span', class_='detections')
            if detection_elem:
                detection_text = detection_elem.get_text().strip()
                match = re.search(r'(\d+)', detection_text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0
    
    def _extract_vt_last_analysis(self, soup: BeautifulSoup) -> str:
        """Extract last analysis date from VirusTotal"""
        try:
            analysis_elem = soup.find('span', class_='last-analysis')
            if analysis_elem:
                return analysis_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _collect_abuseipdb_data(self, target: str) -> Dict[str, Any]:
        """Collect data from AbuseIPDB"""
        try:
            url = f"{self.osint_sources['abuseipdb']}{target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                data = {
                    'url': url,
                    'accessible': True,
                    'abuse_confidence': self._extract_abuse_confidence(soup),
                    'country': self._extract_abuse_country(soup),
                    'isp': self._extract_abuse_isp(soup),
                    'usage_type': self._extract_abuse_usage_type(soup)
                }
                
                return data
            else:
                return {'url': url, 'accessible': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.warning(f"AbuseIPDB data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_abuse_confidence(self, soup: BeautifulSoup) -> int:
        """Extract abuse confidence percentage from AbuseIPDB"""
        try:
            confidence_elem = soup.find('div', class_='confidence')
            if confidence_elem:
                confidence_text = confidence_elem.get_text().strip()
                match = re.search(r'(\d+)%', confidence_text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0
    
    def _extract_abuse_country(self, soup: BeautifulSoup) -> str:
        """Extract country from AbuseIPDB"""
        try:
            country_elem = soup.find('span', class_='country')
            if country_elem:
                return country_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _extract_abuse_isp(self, soup: BeautifulSoup) -> str:
        """Extract ISP from AbuseIPDB"""
        try:
            isp_elem = soup.find('span', class_='isp')
            if isp_elem:
                return isp_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _extract_abuse_usage_type(self, soup: BeautifulSoup) -> str:
        """Extract usage type from AbuseIPDB"""
        try:
            usage_elem = soup.find('span', class_='usage-type')
            if usage_elem:
                return usage_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _collect_threatcrowd_data(self, target: str) -> Dict[str, Any]:
        """Collect data from ThreatCrowd"""
        try:
            url = f"{self.osint_sources['threatcrowd']}{target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                data = {
                    'url': url,
                    'accessible': True,
                    'malicious': self._extract_threatcrowd_malicious(soup),
                    'resolutions': self._extract_threatcrowd_resolutions(soup),
                    'hashes': self._extract_threatcrowd_hashes(soup)
                }
                
                return data
            else:
                return {'url': url, 'accessible': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.warning(f"ThreatCrowd data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_threatcrowd_malicious(self, soup: BeautifulSoup) -> bool:
        """Extract malicious status from ThreatCrowd"""
        try:
            malicious_elem = soup.find('span', class_='malicious')
            if malicious_elem:
                return 'yes' in malicious_elem.get_text().lower()
        except Exception:
            pass
        return False
    
    def _extract_threatcrowd_resolutions(self, soup: BeautifulSoup) -> List[str]:
        """Extract DNS resolutions from ThreatCrowd"""
        resolutions = []
        try:
            resolution_elements = soup.find_all('a', class_='resolution')
            for elem in resolution_elements:
                resolutions.append(elem.get_text().strip())
        except Exception:
            pass
        return resolutions
    
    def _extract_threatcrowd_hashes(self, soup: BeautifulSoup) -> List[str]:
        """Extract associated hashes from ThreatCrowd"""
        hashes = []
        try:
            hash_elements = soup.find_all('a', class_='hash')
            for elem in hash_elements:
                hashes.append(elem.get_text().strip())
        except Exception:
            pass
        return hashes
    
    def _collect_otx_data(self, target: str) -> Dict[str, Any]:
        """Collect data from AlienVault OTX"""
        try:
            url = f"{self.osint_sources['otx']}{target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                data = {
                    'url': url,
                    'accessible': True,
                    'pulse_count': self._extract_otx_pulse_count(soup),
                    'reputation': self._extract_otx_reputation(soup),
                    'tags': self._extract_otx_tags(soup)
                }
                
                return data
            else:
                return {'url': url, 'accessible': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.warning(f"OTX data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_otx_pulse_count(self, soup: BeautifulSoup) -> int:
        """Extract pulse count from OTX"""
        try:
            pulse_elem = soup.find('span', class_='pulse-count')
            if pulse_elem:
                pulse_text = pulse_elem.get_text().strip()
                match = re.search(r'(\d+)', pulse_text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0
    
    def _extract_otx_reputation(self, soup: BeautifulSoup) -> str:
        """Extract reputation from OTX"""
        try:
            reputation_elem = soup.find('span', class_='reputation')
            if reputation_elem:
                return reputation_elem.get_text().strip()
        except Exception:
            pass
        return 'Unknown'
    
    def _extract_otx_tags(self, soup: BeautifulSoup) -> List[str]:
        """Extract tags from OTX"""
        tags = []
        try:
            tag_elements = soup.find_all('span', class_='tag')
            for elem in tag_elements:
                tags.append(elem.get_text().strip())
        except Exception:
            pass
        return tags
    
    def _collect_whois_data(self, target: str) -> Dict[str, Any]:
        """Collect WHOIS data for target"""
        try:
            # This is a simplified WHOIS implementation
            # In production, you would use a proper WHOIS library
            import socket
            
            whois_data = {
                'target': target,
                'whois_available': False
            }
            
            # Try to get basic network information
            try:
                hostname = socket.gethostbyaddr(target)
                whois_data['hostname'] = hostname[0]
                whois_data['aliases'] = hostname[1]
            except socket.herror:
                pass
            
            return whois_data
            
        except Exception as e:
            logger.warning(f"WHOIS data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _collect_dns_data(self, target: str) -> Dict[str, Any]:
        """Collect DNS data for target"""
        try:
            import socket
            
            dns_data = {
                'target': target,
                'a_records': [],
                'mx_records': [],
                'txt_records': []
            }
            
            # Get A records
            try:
                a_records = socket.gethostbyname_ex(target)
                dns_data['a_records'] = a_records[2]
            except socket.gaierror:
                pass
            
            return dns_data
            
        except Exception as e:
            logger.warning(f"DNS data collection failed: {str(e)}")
            return {'error': str(e)}
    
    def _save_osint_data(self, scan_id: int, osint_data: Dict[str, Any]) -> None:
        """Save OSINT data to database"""
        try:
            # Create a system log entry for OSINT data
            from app.models import SystemLog
            
            log_entry = SystemLog(
                level='info',
                component='osint_scanner',
                message=f"OSINT data collected for scan {scan_id}",
                details=json.dumps(osint_data)
            )
            
            db.session.add(log_entry)
            db.session.commit()
            
            logger.info(f"Saved OSINT data for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save OSINT data: {str(e)}")
            raise
