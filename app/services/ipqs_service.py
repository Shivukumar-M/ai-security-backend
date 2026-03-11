# backend/app/services/ipqs_service.py
# (Contents similar to APIVoidService, but targeting IPQualityScore's domain/URL endpoint)
import requests
from app.config import settings
from tenacity import retry, stop_after_attempt, wait_fixed
import logging

logger = logging.getLogger(__name__)

class IPQSService:
    BASE_URL = "https://www.ipqualityscore.com/api/json/url/"

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def check_url_risk(self, url: str) -> dict:
        """Simulates calling the IPQualityScore URL risk API."""
        api_key = settings.IPQS_API_KEY
        if not api_key:
            logger.warning("IPQS API key not set. Returning simulated result.")
            return {"score": 2, "malicious": False}

        url_no_protocol = url.split('://')[-1]
        
        try:
            response = requests.get(f"{self.BASE_URL}{api_key}/{url_no_protocol}", timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # --- Simplified Mocking Logic ---
            malicious = "phish" in url.lower() or "scam" in url.lower()
            score = 95 if malicious else 5

            return {"score": score, "malicious": malicious, "raw_data": data}

        except requests.exceptions.RequestException as e:
            logger.error(f"IPQS request failed for {url}: {e}")
            raise