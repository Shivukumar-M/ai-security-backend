# backend/app/routers/rag.py

from fastapi import APIRouter, Depends
from app.dependencies import CurrentUser
from app.rag_engine.rag_utils import RAGUtility
from app.schemas.rag_schema import RAGExplanationRequest, RAGExplanationResponse

router = APIRouter(prefix="/rag", tags=["RAG Threat Explanation"])
rag_utility = RAGUtility()


@router.post("/explain", response_model=RAGExplanationResponse)
def get_threat_explanation(
    request: RAGExplanationRequest,
    current_user: CurrentUser
):
    """
    Generates a contextual, human-readable, MITRE-mapped AI explanation
    for URLs, Files, or IDS alerts using Gemini + RAG.
    """

    return rag_utility.generate_explanation(
        threat_type=request.threat_type,
        context_data=request.context_data
    )
