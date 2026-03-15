import asyncio
import logging
import socket
import httpx
import dns.resolver

from typing import Dict, Any, Optional

from app.services.urlhaus_service import URLHausService
from app.services.virustotal_service import VirusTotalService
from app.models.urlscan_model import URLScanResult
from app.dependencies import DBSession

from app.utils.helper import load_ml_model
from app.ml.feature_detector import URLFeatureExtractor

logger = logging.getLogger(__name__)

urlhaus_service = URLHausService()
vt_service = VirusTotalService()


class URLAnalyzerService:
    def __init__(self):
        self.model = load_ml_model("url_model.pkl")

        try:
            self.vectorizer = load_ml_model("vectorizer.pkl")
        except Exception:
            logger.warning("No vectorizer found. Using numeric-only features.")
            self.vectorizer = None

        self.extractor = URLFeatureExtractor(self.model, self.vectorizer)

    # --------------------------------------------------
    # DNS LOOKUP
    # --------------------------------------------------
    @staticmethod
    def nslookup_ip(hostname: str) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(hostname, "A")
            return answers[0].to_text()
        except Exception:
            return None

    # --------------------------------------------------
    # GEOIP LOOKUP  ✅ FIXED & REGISTERED
    # --------------------------------------------------
    async def geoip_lookup(self, ip: Optional[str]) -> Dict[str, Any]:
        if not ip:
            return {}

        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"http://ip-api.com/json/{ip}")
                data = resp.json()

                if data.get("status") != "success":
                    return {}

                return {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }

        except Exception:
            return {}

    # --------------------------------------------------
    # URL RESOLUTION
    # --------------------------------------------------
    async def resolve_url(self, url: str) -> Dict[str, Any]:
        result = {
            "reachable": False,
            "http_status": None,
            "ip_address": None,
            "error": None,
        }

        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(url)

                result["reachable"] = response.status_code < 600
                result["http_status"] = response.status_code

                hostname = response.url.host

                try:
                    ip_address = socket.gethostbyname(hostname)
                except Exception:
                    ip_address = self.nslookup_ip(hostname)

                result["ip_address"] = ip_address

        except Exception as e:
            result["error"] = str(e)

        return result

    # --------------------------------------------------
    async def ml_predict(self, url: str) -> Dict[str, Any]:
        try:
            X = self.extractor.transform(url)
            score = float(self.model.predict_proba(X)[0][1])
            verdict = "Malicious" if score >= 0.70 else "Legitimate"
            return {"ml_verdict": verdict, "ml_score": score}
        except Exception:
            logger.exception("ML Prediction Error")
            return {"ml_verdict": "Error", "ml_score": 0.0}

    # --------------------------------------------------
    async def scan_and_analyze(self, url: str, user_id: int, db: DBSession):

        # --------------------------------------------------
        # URL CHECK + DNS + GEOIP
        # --------------------------------------------------
        url_check = await self.resolve_url(url)
        geoip_data = await self.geoip_lookup(url_check.get("ip_address"))

        # --------------------------------------------------
        # URL NOT REACHABLE
        # --------------------------------------------------
        if not url_check["reachable"] or url_check["http_status"] in (404, 410):
            scan_item = URLScanResult(
                user_id=user_id,
                target_url=url,
                ml_verdict="N/A",
                ml_score=0.0,
                final_verdict="URL Not Reachable",
                urlhaus_status="not_checked",
                resolved_ip=url_check.get("ip_address"),
                http_status_code=url_check.get("http_status"),
                url_reachable=False,
                vt_details={
                    "error": url_check.get("error"),
                    "geoip": geoip_data,
                },
                engine_results={},
                engine_explanations={},
                mitre_techniques=[],
            )

            db.add(scan_item)
            db.commit()
            db.refresh(scan_item)
            return scan_item

        # --------------------------------------------------
        # PARALLEL ANALYSIS
        # --------------------------------------------------
        ml_res, urlhaus_res, vt_res = await asyncio.gather(
            self.ml_predict(url),
            urlhaus_service.check_url_haus(url),
            vt_service.scan_url(url),
            return_exceptions=True,
        )

        vt_data = vt_res if isinstance(vt_res, dict) else {}

        final_verdict = (
            "Threat Detected"
            if vt_data.get("malicious_count", 0) > 0
            else "Safe"
        )

        scan_item = URLScanResult(
            user_id=user_id,
            target_url=url,
            ml_verdict=ml_res.get("ml_verdict"),
            ml_score=float(ml_res.get("ml_score", 0.0)),
            urlhaus_status=urlhaus_res.get("status") if isinstance(urlhaus_res, dict) else "api_error",
            final_verdict=final_verdict,
            resolved_ip=url_check.get("ip_address"),
            http_status_code=url_check.get("http_status"),
            url_reachable=True,
            vt_details={
                **vt_data,
                "geoip": geoip_data,   # ✅ FRONTEND NEEDS THIS
            },
            engine_results=vt_data.get("engine_results", {}),
            engine_explanations={},
            mitre_techniques=[],
        )

        db.add(scan_item)
        db.commit()
        db.refresh(scan_item)
        return scan_item
