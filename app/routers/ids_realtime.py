from fastapi import APIRouter, Body
from app.middleware.ids_middleware import LIVE_ALERTS
from app.rag_engine.rag_utils import RAGUtility

router = APIRouter(prefix="/ids/realtime", tags=["Real-Time IDS"])

rag = RAGUtility()


@router.get("/alerts")
def get_live_alerts():
    return {
        "count": len(LIVE_ALERTS),
        "alerts": LIVE_ALERTS[-10:]
    }


@router.post("/explain")
def explain_ids_alert(
    payload: dict = Body(...)
):
    """
    Explain a single IDS alert using AI (RAG).
    """
    alert = payload.get("alert")
    if not alert:
        return {"error": "Missing alert data"}

    threat_type = ", ".join(alert.get("attack_types", ["Unknown Threat"]))

    explanation = rag.generate_explanation(
        threat_type=threat_type,
        context_data=alert
    )

    return explanation
