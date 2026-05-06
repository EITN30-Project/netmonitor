from fastapi import APIRouter, Query

from ..analysis_metrics import collector

router = APIRouter()


@router.get("/analysis/metrics")
def get_analysis_metrics(limit: int = Query(120, ge=1, le=600)):
    return {"points": collector.get_points(limit=limit)}
