# backend/app/services/whois_lookup.py
import whois
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime, timedelta
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

# Note: You may need to install the 'python-whois' library: pip install python-whois

logger = logging.getLogger(__name__)

class WHOISLookup:
    """
    Performs a WHOIS query to retrieve domain registration and expiry information.
    """
    
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2))
    async def lookup_domain(self, url: str) -> Dict[str, Any]:
        """
        Extracts the domain and performs WHOIS lookup.
        """
        hostname = urlparse(url).netloc
        domain = hostname.split('www.')[-1]
        
        if not domain:
            return {"error": "Invalid URL or domain", "domain_age_days": 0}

        try:
            w = whois.whois(domain)
            
            # Handle potential datetime or list responses
            creation_date_raw = w.creation_date
            expiry_date_raw = w.expiration_date
            
            # Normalize dates to single datetime object if a list is returned
            creation_date = creation_date_raw[0] if isinstance(creation_date_raw, list) else creation_date_raw
            
            # Calculate domain age
            domain_age_days = (datetime.now() - creation_date).days if creation_date and isinstance(creation_date, datetime) else 0

            return {
                "registrar": w.registrar,
                "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else "N/A",
                "expiration_date": expiry_date_raw[0].strftime('%Y-%m-%d') if isinstance(expiry_date_raw, list) and expiry_date_raw[0] else "N/A",
                "domain_age_days": domain_age_days,
                "is_newly_registered": domain_age_days < 30, # Common indicator of phishing
                "privacy_protected": bool(w.registrar and 'privacy' in w.registrar.lower())
            }

        except whois.parser.PywhoisError as e:
            return {"error": "WHOIS lookup failed or domain not found", "domain_age_days": 0}
        except Exception as e:
            logger.error(f"WHOIS check failed for {url}: {e}")
            return {"error": str(e), "domain_age_days": 0}