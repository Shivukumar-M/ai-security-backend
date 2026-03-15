# backend/app/services/virustotal_service.py

import httpx
import base64
import logging
from app.config import settings
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)


class VirusTotalService:
    """
    Handles URL + File hash scanning using VirusTotal API v3.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    # ---------------------------------------------------------
    # Helper: Convert URL → VT encoded ID
    # ---------------------------------------------------------
    def _url_to_id(self, url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return encoded

    # ---------------------------------------------------------
    # URL SCAN
    # ---------------------------------------------------------
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2))
    async def scan_url(self, url: str) -> dict:

        if not self.api_key:
            logger.warning("⚠️ Missing VirusTotal API Key")
            return {"error": "Missing API Key"}

        url_id = self._url_to_id(url)
        endpoint = f"{self.BASE_URL}/urls/{url_id}"

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(endpoint, headers=self.headers, timeout=15)

                if response.status_code == 404:
                    return {
                        "verdict": "Unscanned",
                        "stats": {},
                        "engine_results": {}
                    }

                response.raise_for_status()
                data = response.json()

                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                engines = attributes.get("last_analysis_results", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0:
                    verdict = "Malicious"
                elif suspicious > 0:
                    verdict = "Suspicious"
                else:
                    verdict = "Clean"

                redirects = attributes.get("redirect_chain", [])
                redirect_urls = [
                    x.get("url") for x in redirects if isinstance(x, dict)
                ]

                return {
                    "verdict": verdict,
                    "malicious_count": malicious,
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),

                    "scan_date": attributes.get("last_analysis_date"),
                    "permalink": data.get("data", {}).get("links", {}).get("self"),

                    "title": attributes.get("title"),
                    "tags": attributes.get("tags", []),
                    "content_type": attributes.get("content_type"),
                    "server": attributes.get("server"),
                    "asn": attributes.get("asn"),
                    "country": attributes.get("country"),
                    "last_http_response_code": attributes.get("last_http_response_code"),

                    "redirect_chain": redirect_urls,
                    "engine_results": engines,
                }

            except httpx.HTTPStatusError as e:
                logger.error(f"VT API Error (URL): {e}")
                return {"error": f"API Error: {str(e)}"}

            except Exception as e:
                logger.error(f"VT URL scan failed: {e}")
                return {"error": "Connection Failed"}

    # ---------------------------------------------------------
    # FILE HASH SCAN
    # ---------------------------------------------------------
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2))
    async def scan_file_hash(self, file_hash: str) -> dict:

        if not self.api_key:
            logger.warning("⚠️ Missing API Key for File Hash Scan")
            return {"error": "Missing API Key"}

        endpoint = f"{self.BASE_URL}/files/{file_hash}"

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(endpoint, headers=self.headers, timeout=15)

                if response.status_code == 404:
                    return {"verdict": "Unknown/Clean", "stats": {}}

                response.raise_for_status()
                data = response.json()

                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious_count = stats.get("malicious", 0)
                verdict = "Malicious" if malicious_count > 0 else "Clean"

                # ⭐ NEW: consistent file name
                file_name = (
                    attributes.get("meaningful_name")
                    or attributes.get("names", [None])[0]
                    or "Unknown"
                )

                # ⭐ NEW: permalink support
                permalink = data.get("data", {}).get("links", {}).get("self")

                # ⭐ NEW: file properties (frontend uses this)
                file_props = {
                    "type_description": attributes.get("type_description"),
                    "size": attributes.get("size"),
                    "magic": attributes.get("magic"),
                    "sha1": attributes.get("sha1"),
                    "md5": attributes.get("md5"),
                }

                return {
                    "verdict": verdict,
                    "malicious_count": malicious_count,
                    "total_engines": sum(stats.values()),

                    "file_name": file_name,
                    "type_description": attributes.get("type_description", "Unknown"),
                    "scan_date": attributes.get("last_analysis_date"),
                    "permalink": permalink,

                    "file_properties": file_props,

                    "engine_results": attributes.get("last_analysis_results", {})
                }

            except httpx.HTTPStatusError as e:
                logger.error(f"VT File Error: {e}")
                return {"error": "API Error"}

            except Exception as e:
                logger.error(f"VT File scan failed: {e}")
                return {"error": "Connection Failed"}
