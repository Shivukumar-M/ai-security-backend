# backend/app/services/apivoid_service.py
import requests
from app.config import settings
from tenacity import retry, stop_after_attempt, wait_fixed
import logging

logger = logging.getLogger(__name__)

class APIVoidService:
    BASE_URL = "https://www.apivoid.com/api/url-rep/v1/"

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def check_url_reputation(self, url: str) -> dict:
        """
        Simulates calling the APIVoid URL reputation API.
        Returns a dictionary containing the score and verdict.
        """
        api_key = settings.APIVOID_API_KEY
        if not api_key:
            logger.warning("APIVoid API key not set. Returning simulated result.")
            return {"score": 5, "verdict": "Simulated Low Risk"}

        params = {
            "key": api_key,
            "url": url
        }
        
        try:
            # Simulate a request; in reality, you'd use aiohttp for async
            # For simplicity with FastAPI, we use sync requests in a background task
            response = requests.get(self.BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            # --- Simplified Mocking Logic ---
            if "error" in data:
                 # If a real error occurs, fall back to a default low score
                logger.error(f"APIVoid Error for {url}: {data.get('error')}")
                return {"score": 5, "verdict": "Simulated API Error (Low Risk)"}
            
            # Extract relevant info: mock score based on length/complexity
            score = (len(url) % 100) / 10
            verdict = "Suspicious" if score > 8 else "Clean"

            return {"score": int(score * 10), "verdict": verdict, "raw_data": data}

        except requests.exceptions.RequestException as e:
            logger.error(f"APIVoid request failed for {url}: {e}")
            raise