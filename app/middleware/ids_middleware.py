from collections import defaultdict
import time
from fastapi.responses import JSONResponse

from app.services.ids_engine import IDSEngineService

ids_engine = IDSEngineService()

# ==============================
# GLOBAL STATE
# ==============================
REQUEST_TRACKER = defaultdict(list)
LIVE_ALERTS = []

BLOCKED_IPS = {}
BLOCK_DURATION = 300  # seconds

DDOS_ALERTED_IPS = {}         # ip -> timestamp
DDOS_ALERT_TTL = 600          # seconds
DDOS_THRESHOLD = 80           # requests / 10s window


async def ids_middleware(request, call_next):
    now = time.time()

    # =================================================
    # ALLOW IDS DASHBOARD ALWAYS
    # =================================================
    if request.url.path.startswith("/api/v1/ids/realtime"):
        return await call_next(request)

    # =================================================
    # CLIENT IP
    # =================================================
    ip = request.headers.get("x-forwarded-for")
    ip = ip.split(",")[0].strip() if ip else request.client.host
    endpoint = request.url.path

    # =================================================
    # BLOCK CHECK
    # =================================================
    unblock_time = BLOCKED_IPS.get(ip)
    if unblock_time and now < unblock_time:
        return JSONResponse(
            status_code=404,
            content={"detail": "Page Not Found"},
        )
    elif unblock_time:
        del BLOCKED_IPS[ip]

    # =================================================
    # REQUEST RATE TRACKING (10s window)
    # =================================================
    REQUEST_TRACKER[ip].append(now)
    REQUEST_TRACKER[ip] = [t for t in REQUEST_TRACKER[ip] if now - t < 10]

    is_ddos = len(REQUEST_TRACKER[ip]) > DDOS_THRESHOLD

    # =================================================
    # PAYLOAD INSPECTION
    # =================================================
    payload = ""
    try:
        body = await request.body()
        payload = body.decode(errors="ignore").lower()
        request.state.payload = payload
    except Exception:
        request.state.payload = ""

    # =================================================
    # IDS EVENT
    # =================================================
    event = {
        "ip": ip,
        "endpoint": endpoint,
        "request_rate": len(REQUEST_TRACKER[ip]),
        "sql_injection": "or 1=1" in payload or "union select" in payload,
        "xss": "<script>" in payload or "javascript:" in payload,
        "repeat_offender": is_ddos,
    }

    result = ids_engine.analyze_single_event(event)
    threat = result.get("threat", {})
    attack_types = threat.get("attack_types", [])

    # =================================================
    # CLEAN EXPIRED DDoS ALERTS
    # =================================================
    DDOS_ALERTED_IPS.update({
        ip_: ts for ip_, ts in DDOS_ALERTED_IPS.items()
        if now - ts < DDOS_ALERT_TTL
    })

    # =================================================
    # LOG ALERTS
    # =================================================
    should_log = True

    if "DDoS" in attack_types:
        if ip in DDOS_ALERTED_IPS:
            should_log = False
        else:
            DDOS_ALERTED_IPS[ip] = now

    if should_log and threat.get("severity") in ["Medium", "High", "Critical"]:
        LIVE_ALERTS.append({
            "ip": ip,
            "endpoint": endpoint,
            "timestamp": now,
            "attack_types": attack_types,
            "severity": threat.get("severity"),
            "description": threat.get("description"),
            "recommended_action": threat.get("recommended_action"),
            "mitre_techniques": threat.get("mitre_techniques", []),
            "correlated_attack": result["correlation"]["correlated"],
        })
        LIVE_ALERTS[:] = LIVE_ALERTS[-50:]

    # =================================================
    # BLOCK ONLY DDoS CRITICAL
    # =================================================
    if threat.get("severity") == "Critical" and "DDoS" in attack_types:
        BLOCKED_IPS[ip] = now + BLOCK_DURATION

    return await call_next(request)
