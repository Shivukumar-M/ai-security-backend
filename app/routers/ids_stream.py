# backend/app/routers/ids_stream.py

from fastapi import APIRouter
from app.services.ids_engine import IDSEngineService
from app.dependencies import CurrentUser

router = APIRouter(prefix="/ids/stream", tags=["Streaming IDS"])

ids_engine = IDSEngineService()


@router.post("/analyze")
async def analyze_stream_event(
    event: dict,
    current_user: CurrentUser
):
    """
    Analyze a single IDS event in streaming mode.
    Reuses unified IDS engine (v2/v3).
    """
    if not isinstance(event, dict):
        return {"error": "Invalid event format"}

    return ids_engine.analyze_single_event(event)
