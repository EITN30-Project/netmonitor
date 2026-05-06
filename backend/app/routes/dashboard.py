from fastapi import APIRouter, HTTPException

from ..analysis_metrics import collector
from .. import firewall

router = APIRouter()


@router.get("/dashboard/stats")
def get_dashboard_stats():
    # Throughput: use latest available sample from the collector.
    throughput_kbps = 0.0
    try:
        pts = collector.get_points(limit=1)
        if pts:
            v = pts[-1].get("throughput_kbps")
            if isinstance(v, (int, float)):
                throughput_kbps = float(v)
    except Exception:
        throughput_kbps = 0.0

    # Blocked packets: sum nftables drop rule counters (best-effort).
    blocked_packets_error = None
    try:
        counters = firewall.get_netmonitor_counters()
        blocked_packets_total = int(counters.get("blocked_packets_total", 0))
    except firewall.FirewallError as exc:
        blocked_packets_total = 0
        blocked_packets_error = str(exc)
    except Exception:
        blocked_packets_total = 0
        blocked_packets_error = "Failed to load blocked packet counters"

    payload = {
        "blocked_packets_total": blocked_packets_total,
        "throughput_kbps": throughput_kbps,
    }

    if blocked_packets_error:
        payload["blocked_packets_error"] = blocked_packets_error

    return payload
