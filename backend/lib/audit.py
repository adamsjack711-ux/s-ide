"""Network Audit — Phase 2 of the LAN sweep.

Each live host gets a small focused port scan against well-known risky
services (FTP/Telnet/SMB/RDP/etc.). Per-host risk level is the worst tier
that any open port carried.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Callable

from lib import scanner

# {port: (service_name, risk_tier)}
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21:    ("FTP",           "high"),
    23:    ("Telnet",        "critical"),
    25:    ("SMTP",          "medium"),
    80:    ("HTTP",          "low"),
    110:   ("POP3",          "medium"),
    111:   ("RPC",           "medium"),
    143:   ("IMAP",          "medium"),
    445:   ("SMB",           "critical"),
    1433:  ("MSSQL",         "high"),
    1521:  ("Oracle DB",     "high"),
    3306:  ("MySQL",         "high"),
    3389:  ("RDP",           "critical"),
    5432:  ("PostgreSQL",    "medium"),
    5900:  ("VNC",           "high"),
    6379:  ("Redis",         "critical"),
    8080:  ("HTTP-Alt",      "low"),
    9200:  ("Elasticsearch", "high"),
    27017: ("MongoDB",       "critical"),
}

RISK_TIERS = ("critical", "high", "medium", "low")


def worst_tier(tiers: list[str]) -> str:
    """Pick the most severe tier present, or 'clean' if none."""
    for tier in RISK_TIERS:
        if any(t == tier for t in tiers):
            return tier
    return "clean"


def audit_stream(
    hosts: list[tuple[str, str, bool]],   # [(ip, hostname, is_self), ...]
    *,
    on_host:     Callable[[str, str, bool, list[dict], str], None],
    on_progress: Callable[[int, int, int], None],   # (done_jobs, total_jobs, hosts_done)
    should_stop: Callable[[], bool],
    port_timeout: float = 0.8,
    num_threads:  int   = 128,
) -> None:
    """Flat (host, port) work queue + thread pool.

    Emits one `on_host(ip, hostname, is_self, open_risky, risk_level)` event
    per host as soon as that host's last port has been probed.
    """
    risky_ports = sorted(RISKY_PORTS)
    if not hosts or not risky_ports:
        return

    per_host: dict[str, dict] = {
        ip: {"hostname": hn, "is_self": iself,
             "open": [], "remaining": len(risky_ports)}
        for ip, hn, iself in hosts
    }

    work_q: queue.Queue[tuple[str, int]] = queue.Queue()
    for ip in per_host:
        for port in risky_ports:
            work_q.put((ip, port))

    total_jobs  = len(hosts) * len(risky_ports)
    done_jobs   = 0
    hosts_done  = 0
    state_lock  = threading.Lock()

    def worker():
        nonlocal done_jobs, hosts_done
        while not should_stop():
            try:
                ip, port = work_q.get_nowait()
            except queue.Empty:
                return
            try:
                hit = scanner.probe(ip, port, port_timeout)
            except Exception:
                hit = None

            emit: tuple | None = None
            with state_lock:
                state = per_host[ip]
                if hit is not None:
                    svc, tier = RISKY_PORTS[port]
                    state["open"].append({"port": port, "service": svc, "risk": tier})
                state["remaining"] -= 1
                if state["remaining"] == 0:
                    hosts_done += 1
                    open_sorted = sorted(state["open"], key=lambda x: x["port"])
                    tiers = [o["risk"] for o in open_sorted]
                    emit = (ip, state["hostname"], state["is_self"],
                            open_sorted, worst_tier(tiers))
                done_jobs += 1
                snap_done, snap_total, snap_hosts_done = done_jobs, total_jobs, hosts_done

            if emit is not None:
                try:
                    on_host(*emit)
                except Exception:
                    pass
            try:
                on_progress(snap_done, snap_total, snap_hosts_done)
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(num_threads, total_jobs))]
    for t in threads: t.start()
    for t in threads: t.join()
