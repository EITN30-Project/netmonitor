from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from . import firewall


@dataclass(frozen=True)
class MetricsPoint:
    ts: str
    throughput_mbps: Optional[float]
    latency_ms: Optional[float]


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_proc_net_dev(text: str) -> dict[str, tuple[int, int]]:
    # Returns iface -> (rx_bytes, tx_bytes)
    result: dict[str, tuple[int, int]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        if line.startswith("Inter-") or line.startswith("face"):
            continue
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        cols = rest.split()
        if len(cols) < 16:
            continue
        try:
            rx_bytes = int(cols[0])
            tx_bytes = int(cols[8])
        except ValueError:
            continue
        result[iface] = (rx_bytes, tx_bytes)
    return result


def _ping_latency_ms(host: str) -> Optional[float]:
    host = host.strip()
    if not host:
        return None

    is_windows = os.name == "nt"
    cmd = (
        ["ping", "-n", "1", "-w", "1000", host]
        if is_windows
        else ["ping", "-c", "1", "-W", "1", host]
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return None

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    # Linux/macOS: "time=12.3 ms". Windows: "Average = 12ms".
    m = re.search(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", out, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None

    m = re.search(r"Average\s*=\s*([0-9]+)\s*ms", out, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None

    return None


class AnalysisMetricsCollector:
    def __init__(self, max_points: int = 300):
        self._lock = threading.Lock()
        self._points: deque[MetricsPoint] = deque(maxlen=max_points)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._last_bytes_total: Optional[int] = None
        self._last_time: Optional[float] = None
        self._iface: Optional[str] = os.getenv("ANALYSIS_IFACE")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="analysis-metrics", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def get_points(self, limit: int = 120) -> list[dict[str, Any]]:
        with self._lock:
            pts = list(self._points)[-max(1, int(limit)) :]
        return [
            {
                "ts": p.ts,
                "throughput_mbps": p.throughput_mbps,
                "latency_ms": p.latency_ms,
            }
            for p in pts
        ]

    def _run(self) -> None:
        sample_interval = float(os.getenv("ANALYSIS_SAMPLE_INTERVAL", "1"))
        ping_host = os.getenv("ANALYSIS_PING_HOST") or os.getenv("BASE_IP") or "8.8.8.8"

        ssh_client_ctx = None
        ssh_client = None
        ssh_retry_at = 0.0

        try:
            while not self._stop.is_set():
                now = time.time()

                throughput_mbps = None
                if ssh_client is not None:
                    try:
                        out, _, _ = firewall._run_remote(ssh_client, ["cat", "/proc/net/dev"])
                        parsed = _parse_proc_net_dev(out or "")
                        if parsed:
                            iface = self._iface
                            if not iface or iface not in parsed:
                                # Pick a reasonable default (first non-loopback interface).
                                iface = next((k for k in parsed.keys() if k != "lo"), None)
                                self._iface = iface

                            if iface and iface in parsed:
                                rx, tx = parsed[iface]
                                total = rx + tx
                                if self._last_bytes_total is not None and self._last_time is not None:
                                    dt = max(0.001, now - self._last_time)
                                    delta_bytes = max(0, total - self._last_bytes_total)
                                    bps = (delta_bytes * 8.0) / dt
                                    throughput_mbps = bps / 1_000_000.0

                                self._last_bytes_total = total
                                self._last_time = now
                    except Exception:
                        throughput_mbps = None
                        # If SSH seems broken, drop it and retry later.
                        try:
                            if ssh_client_ctx is not None:
                                ssh_client_ctx.__exit__(None, None, None)
                        except Exception:
                            pass
                        ssh_client_ctx = None
                        ssh_client = None
                        ssh_retry_at = now + 10.0

                latency_ms = _ping_latency_ms(ping_host)

                point = MetricsPoint(ts=_utc_iso_now(), throughput_mbps=throughput_mbps, latency_ms=latency_ms)
                with self._lock:
                    self._points.append(point)

                # Best-effort SSH connect for throughput sampling (done *after* appending
                # a point so latency shows up even when SSH is unavailable).
                if ssh_client is None and time.time() >= ssh_retry_at:
                    try:
                        ssh_client_ctx = firewall._ssh_client()  # re-use existing SSH config
                        ssh_client = ssh_client_ctx.__enter__()
                        self._last_bytes_total = None
                        self._last_time = None
                    except Exception:
                        ssh_client_ctx = None
                        ssh_client = None
                        ssh_retry_at = time.time() + 10.0

                self._stop.wait(sample_interval)
        finally:
            if ssh_client is not None and ssh_client_ctx is not None:
                try:
                    ssh_client_ctx.__exit__(None, None, None)
                except Exception:
                    pass


collector = AnalysisMetricsCollector()
