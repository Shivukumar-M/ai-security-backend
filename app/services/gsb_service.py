# backend/app/services/gsb_service.py
# (Contents similar to APIVoidService, for Google Safe Browsing)
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class GSBService:
    # Google Safe Browsing requires a specific API format, here we mock the response structure
    
    async def check_safe_browsing(self, url: str) -> dict:
        """Simulates calling the Google Safe Browsing API."""
        api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        if not api_key:
            logger.warning("GSB API key not set. Returning simulated result.")

        # --- Simplified Mocking Logic ---
        threat_match = "malware" in url.lower() or "abuse" in url.lower()
        
        if threat_match:
            verdict = "MALWARE"
        elif "login" in url.lower() and "?" in url.lower():
            verdict = "PHISHING"
        else:
            verdict = "SAFE"
            
        return {"verdict": verdict}