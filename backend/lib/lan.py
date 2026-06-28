"""LAN-scan helpers — subnet detection, TCP-probe host discovery, ARP cache.

Same techniques used by Network Audit's Phase 1; the audit router imports
from this module.
"""
from __future__ import annotations

import ipaddress
import queue
import re
import socket
import struct
import subprocess
import threading
from collections.abc import Callable

# Ports tried when probing whether a host is alive. Hits on at least one of
# these are common for any LAN device (routers/printers/phones/laptops).
PROBE_PORTS: tuple[int, ...] = (80, 443, 22, 445, 139, 8080, 53, 631, 5000, 7000)


def local_ip() -> str:
    """Return the local IP used to reach the internet (via UDP socket trick)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def subnet_info(ip: str) -> tuple[str, int]:
    """Return (network_base, prefix_len) by parsing `ifconfig`."""
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        out = ""
    for line in out.splitlines():
        if ip in line and "netmask" in line:
            m = re.search(r"netmask\s+(0x[0-9a-f]+|\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            raw = m.group(1)
            if raw.startswith("0x"):
                mask_int = int(raw, 16)
            else:
                parts = [int(x) for x in raw.split(".")]
                mask_int = sum(p << (24 - 8 * i) for i, p in enumerate(parts))
            prefix  = bin(mask_int).count("1")
            ip_int  = struct.unpack("!I", socket.inet_aton(ip))[0]
            net_int = ip_int & mask_int
            base    = socket.inet_ntoa(struct.pack("!I", net_int))
            return base, prefix
    # Fallback: /24
    return ".".join(ip.split(".")[:3]) + ".0", 24


def subnet_hosts(net_base: str, prefix: int, cap: int = 1024) -> list[str]:
    """All usable host IPs in the subnet (capped to avoid pathological scans)."""
    net_int = struct.unpack("!I", socket.inet_aton(net_base))[0]
    num_hosts = min((1 << (32 - prefix)) - 2, cap)
    return [socket.inet_ntoa(struct.pack("!I", net_int + i))
            for i in range(1, num_hosts + 1)]


def arp_cache() -> dict[str, str]:
    """Return {ip: mac} from the system ARP table."""
    cache: dict[str, str] = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return cache
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)", line)
        if m and m.group(2) not in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
            cache[m.group(1)] = m.group(2)
    return cache


def is_alive(ip: str, *, per_port_timeout: float = 0.15) -> bool:
    """Return True if any TCP probe port answers (open or refused — both prove alive)."""
    for port in PROBE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(per_port_timeout)
            err = sock.connect_ex((ip, port))
            if err == 0 or err == 61:   # open or ECONNREFUSED
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def scan_stream(
    targets: list[str],
    arp_initial: dict[str, str],
    *,
    on_host:      Callable[[str, str, str], None],   # (ip, hostname, mac)
    on_progress:  Callable[[int, int, int], None],   # (done, total, found)
    should_stop:  Callable[[], bool],
    num_threads:  int = 128,
) -> list[str]:
    """Threaded TCP-probe sweep. Returns the list of IPs that came up alive."""
    total = len(targets)
    if total == 0:
        return []

    q: queue.Queue[str] = queue.Queue()
    for ip in targets:
        q.put(ip)

    found_ips: list[str] = []
    done = 0
    found = 0
    state_lock = threading.Lock()

    def worker():
        nonlocal done, found
        while not should_stop():
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            alive = False
            try:
                if ip in arp_initial or is_alive(ip):
                    alive = True
            except Exception:
                pass

            host = ""
            if alive:
                host = resolve_hostname(ip)

            with state_lock:
                done += 1
                if alive:
                    found += 1
                    found_ips.append(ip)
                snap_done, snap_total, snap_found = done, total, found

            if alive:
                try:
                    on_host(ip, host, arp_initial.get(ip, ""))
                except Exception:
                    pass
            try:
                on_progress(snap_done, snap_total, snap_found)
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(num_threads, total))]
    for t in threads: t.start()
    for t in threads: t.join()
    return found_ips
