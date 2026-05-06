import csv
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Query

from ..analysis_metrics import collector

router = APIRouter()


@lru_cache(maxsize=1)
def _load_performance_metrics_csv() -> list[dict[str, float]]:
    # repo_root/performance_metrics.csv
    csv_path = Path(__file__).resolve().parents[3] / "performance_metrics.csv"
    if not csv_path.exists():
        return []

    rows: list[dict[str, float]] = []
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            try:
                input_bps = float((raw.get("input_bps") or "0").strip())
                output_bps = float((raw.get("output_bps") or "0").strip())
                rtt_avg_ms = float((raw.get("rtt_avg_ms") or "0").strip())
            except Exception:
                continue
            rows.append(
                {
                    "input_kbps": input_bps / 1_000.0,
                    "output_kbps": output_bps / 1_000.0,
                    "latency_ms": rtt_avg_ms,
                }
            )
    return rows


def _static_plots_payload() -> dict[str, list[dict[str, float]]]:
    rows = _load_performance_metrics_csv()
    if not rows:
        return {"latency_vs_input": [], "output_vs_input": []}

    return {
        "latency_vs_input": [
            {"input_kbps": r["input_kbps"], "latency_ms": r["latency_ms"]} for r in rows
        ],
        "output_vs_input": [
            {"input_kbps": r["input_kbps"], "output_kbps": r["output_kbps"]} for r in rows
        ],
    }


@router.get("/analysis/metrics")
def get_analysis_metrics(limit: int = Query(120, ge=1, le=600)):
    return {
        "points": collector.get_points(limit=limit),
        "static_plots": _static_plots_payload(),
    }
