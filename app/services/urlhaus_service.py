# backend/app/services/urlhaus_service.py

import requests
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

class URLHausService:
    """
    Fully safe URLHaus wrapper.
    Even if URLHaus returns:
    - 400
    - 401
    - HTML instead of JSON
    - Timeout
    It will NEVER crash the application.
    """
    BASE_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    @retry(stop=stop_after_attempt(1))   # Disable retries (speed)
    async def check_url_haus(self, url: str) -> dict:
        try:
            response = requests.post(
                self.BASE_URL,
                data={"url": url},
                timeout=6
            )

            if response.status_code != 200:
                logger.warning(f"URLHaus non-200 response: {response.status_code}")
                return {"status": "api_error", "raw": None}

            try:
                data = response.json()
            except Exception:
                logger.error("URLHaus returned non-JSON body")
                return {"status": "api_error", "raw": None}

            # Normalize official URLHaus statuses
            # https://urlhaus.abuse.ch/api/
            status = data.get("query_status", "unknown")

            if status in ("ok", "success"):
                # Check if malicious campaigns exist
                if data.get("url_status") == "online" and data.get("threat", ""):
                    return {"status": "malicious", "raw": data}
                return {"status": "clean", "raw": data}

            # Unknown or no data
            return {"status": "unknown", "raw": data}

        except Exception as e:
            logger.error(f"URLHaus failed for {url}: {e}")
            return {"status": 'api_error', "raw": None}
