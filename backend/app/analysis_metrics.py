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
    throughput_kbps: Optional[float]
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

        self._last_bytes_total_by_iface: dict[str, int] = {}
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
                "throughput_kbps": p.throughput_kbps,
                "latency_ms": p.latency_ms,
            }
            for p in pts
        ]

    def _run(self) -> None:
        # Load backend/.env (if present) so BASE_IP/ANALYSIS_PING_HOST are available.
        # This keeps the existing 8.8.8.8 fallback but ensures configured values win.
        firewall._load_env_if_present()

        sample_interval = float(os.getenv("ANALYSIS_SAMPLE_INTERVAL", "1"))
        ping_host = os.getenv("ANALYSIS_PING_HOST") or os.getenv("BASE_IP") or "8.8.8.8"

        print(f"Starting analysis metrics collector: sample_interval={sample_interval}s, ping_host={ping_host}")

        ssh_client_ctx = None
        ssh_client = None
        ssh_retry_at = 0.0

        try:
            while not self._stop.is_set():
                now = time.time()

                throughput_kbps = None
                if ssh_client is not None:
                    try:
                        out, _, _ = firewall._run_remote(ssh_client, ["cat", "/proc/net/dev"])
                        parsed = _parse_proc_net_dev(out or "")
                        if parsed:
                            totals: dict[str, int] = {
                                iface: (rx + tx) for iface, (rx, tx) in parsed.items() if iface != "lo"
                            }

                            iface_override = (os.getenv("ANALYSIS_IFACE") or "").strip() or None

                            iface: Optional[str] = None
                            if iface_override and iface_override in totals:
                                iface = iface_override
                            elif self._iface and self._iface in totals:
                                iface = self._iface

                            # If no iface chosen (or preferred iface has no traffic), pick the iface
                            # with the highest observed delta since the last sample. This helps avoid
                            # getting stuck on an inactive iface (e.g., eth0 vs wlan0).
                            if not iface:
                                if self._last_time is not None and self._last_bytes_total_by_iface:
                                    dt = max(0.001, now - self._last_time)
                                    best_iface = None
                                    best_bps = -1.0
                                    for cand_iface, total in totals.items():
                                        prev_total = self._last_bytes_total_by_iface.get(cand_iface)
                                        if prev_total is None:
                                            continue
                                        delta_bytes = max(0, total - prev_total)
                                        bps = (delta_bytes * 8.0) / dt
                                        if bps > best_bps:
                                            best_bps = bps
                                            best_iface = cand_iface
                                    iface = best_iface

                            # Final fallback: choose the iface with the largest total byte counters.
                            if not iface and totals:
                                iface = max(totals.items(), key=lambda kv: kv[1])[0]

                            if iface and iface in totals:
                                if self._last_time is not None:
                                    dt = max(0.001, now - self._last_time)
                                    prev_total = self._last_bytes_total_by_iface.get(iface)
                                    if prev_total is not None:
                                        delta_bytes = max(0, totals[iface] - prev_total)
                                        bps = (delta_bytes * 8.0) / dt
                                        throughput_kbps = bps / 1_000.0

                                self._iface = iface
                                self._last_time = now
                                # Update per-iface counters so we can switch ifaces later.
                                for cand_iface, total in totals.items():
                                    self._last_bytes_total_by_iface[cand_iface] = total
                    except Exception:
                        throughput_kbps = None
                        # If SSH seems broken, drop it and retry later.
                        try:
                            if ssh_client_ctx is not None:
                                ssh_client_ctx.__exit__(None, None, None)
                        except Exception as e:
                            print(f"Error closing SSH client: {e}")
                            pass
                        ssh_client_ctx = None
                        ssh_client = None
                        ssh_retry_at = now + 10.0

                latency_ms = _ping_latency_ms(ping_host)

                point = MetricsPoint(ts=_utc_iso_now(), throughput_kbps=throughput_kbps, latency_ms=latency_ms)
                with self._lock:
                    self._points.append(point)

                # Best-effort SSH connect for throughput sampling (done *after* appending
                # a point so latency shows up even when SSH is unavailable).
                if ssh_client is None and time.time() >= ssh_retry_at:
                    try:
                        ssh_client_ctx = firewall._ssh_client()  # re-use existing SSH config
                        ssh_client = ssh_client_ctx.__enter__()
                        self._last_bytes_total_by_iface.clear()
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
                except Exception as e:
                    print(f"Error closing SSH client: {e}")


collector = AnalysisMetricsCollector()
