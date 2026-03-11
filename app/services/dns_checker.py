# backend/app/services/dns_checker.py
import socket
import dns.resolver
from typing import Dict, Any
import logging
from urllib.parse import urlparse
from tenacity import retry, stop_after_attempt, wait_fixed

# Note: You may need to install 'dnspython': pip install dnspython

logger = logging.getLogger(__name__)

class DNSChecker:
    """
    Checks the DNS records associated with a given URL's domain.
    """
    
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
    async def resolve_domain(self, url: str) -> Dict[str, Any]:
        """
        Extracts the domain and resolves A, MX, and NS records.
        Returns a dictionary of DNS information.
        """
        try:
            # 1. Extract hostname
            hostname = urlparse(url).netloc
            if hostname.startswith('www.'):
                hostname = hostname[4:]
            if not hostname:
                return {"error": "Invalid URL or missing hostname", "ip_address": None}

            # 2. Resolve A (IP) Record
            ip_address = socket.gethostbyname(hostname)

            # 3. Resolve MX (Mail Exchange) and NS (Name Server) records
            mx_records = [str(r.exchange) for r in dns.resolver.resolve(hostname, 'MX')]
            ns_records = [str(r.target) for r in dns.resolver.resolve(hostname, 'NS')]

            return {
                "ip_address": ip_address,
                "domain_resolved": hostname,
                "mx_records": mx_records,
                "ns_records": ns_records,
                "is_active": True,
                "has_custom_mx": len(mx_records) > 0
            }
        
        except dns.resolver.NoAnswer:
            return {"error": "DNS No Answer (Domain might be fresh or inactive)", "is_active": False}
        except Exception as e:
            logger.error(f"DNS check failed for {url}: {e}")
            return {"error": str(e), "ip_address": None}