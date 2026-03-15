# backend/app/services/ssl_checker.py
import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from urllib.parse import urlparse
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

class SSLChecker:
    """
    Checks the SSL/TLS certificate status for a given HTTPS URL.
    """
    
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2))
    async def check_ssl_status(self, url: str) -> Dict[str, Any]:
        """
        Connects to the host and retrieves certificate details.
        """
        hostname = urlparse(url).netloc
        if not url.startswith('https://'):
            return {"status": "HTTP (No SSL)", "validity_days": 0, "issuer": "N/A"}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            # Parse expiry date
            expiry_str = cert['notAfter']
            expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            
            # Calculate remaining days
            time_left = expiry_date - datetime.now()
            validity_days = max(0, time_left.days)

            return {
                "status": "Valid",
                "validity_days": validity_days,
                "issuer": dict(cert['issuer'])[0][0][1],
                "subject": dict(cert['subject'])[0][0][1],
                "is_expired": validity_days <= 0,
                # Phishing indicator: Short validity (< 90 days is sometimes suspicious)
                "is_suspicious_expiry": validity_days < 90 and validity_days > 0 
            }
        
        except ssl.SSLError as e:
            return {"status": "Error/Self-Signed", "validity_days": 0, "error": str(e)}
        except Exception as e:
            logger.error(f"SSL check failed for {url}: {e}")
            return {"status": "Failed to connect", "validity_days": 0, "error": str(e)}