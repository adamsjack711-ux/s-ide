"""Threaded TCP port scanner with service banner detection.

Pure Python — usable from FastAPI websocket handlers, future CLIs, and tests.
"""
from __future__ import annotations

import queue
import socket
import ssl
import threading
from collections.abc import Callable
from typing import Iterable

SERVICES: dict[int, str] = {
    # Mail / file / remote-access
    20:   "FTP-data", 21: "FTP",  22: "SSH",  23: "Telnet",
    25:   "SMTP",     53: "DNS",  67: "DHCP", 68: "DHCP",
    69:   "TFTP",     79: "Finger",
    # Web
    80:   "HTTP",     81: "HTTP-Alt",  82: "HTTP-Alt",
    # Auth / dir / mail
    88:   "Kerberos", 110: "POP3", 111: "RPC",
    113:  "Ident",    119: "NNTP",
    123:  "NTP",      135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DG", 139: "NetBIOS-SSN",
    143:  "IMAP",     161: "SNMP",   162: "SNMP-Trap",
    179:  "BGP",      194: "IRC",
    # Web / mail / LDAP / SMB
    389:  "LDAP",     443: "HTTPS",  445: "SMB",
    465:  "SMTPS",    500: "ISAKMP", 514: "Syslog", 515: "LPR",
    520:  "RIP",
    554:  "RTSP",     587: "SMTP/TLS",
    636:  "LDAPS",    646: "LDP",
    873:  "rsync",
    902:  "VMware",
    993:  "IMAPS",    995: "POP3S",
    # Databases / queues / caches
    1080: "SOCKS",    1194: "OpenVPN", 1352: "Lotus Notes",
    1433: "MSSQL",    1434: "MSSQL-mon",
    1521: "Oracle DB",
    1701: "L2TP",     1723: "PPTP",
    1812: "RADIUS",   1813: "RADIUS-acct",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",   2083: "cPanel-SSL",
    2181: "ZooKeeper",
    2375: "Docker",   2376: "Docker-TLS",
    2483: "Oracle",   2484: "Oracle-SSL",
    3000: "Dev-HTTP", 3001: "Dev-HTTP",
    3128: "Squid",
    3268: "GC-LDAP",  3269: "GC-LDAPS",
    3306: "MySQL",    3389: "RDP",
    4369: "EPMD",     4444: "Metasploit",
    4500: "IPSec-NAT",
    4567: "Sinatra",  4848: "GlassFish",
    5000: "UPnP/AirPlay",
    5001: "iperf",    5009: "AirPort",
    5060: "SIP",      5061: "SIP-TLS",
    5222: "XMPP",     5269: "XMPP-Server",
    5353: "mDNS",
    5432: "PostgreSQL", 5433: "PostgreSQL-Alt",
    5555: "ADB",
    5601: "Kibana",
    5672: "AMQP",     5671: "AMQPS",
    5900: "VNC",      5901: "VNC-1", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6000: "X11",      6379: "Redis",  6443: "Kubernetes-API",
    6660: "IRC",      6667: "IRC",
    6881: "BitTorrent",
    7000: "AirPlay",
    7001: "WebLogic", 7002: "WebLogic-SSL",
    7077: "Spark",
    7474: "Neo4j",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
    8080: "HTTP-Proxy", 8086: "InfluxDB", 8088: "Hadoop",
    8161: "ActiveMQ",
    8443: "HTTPS-Alt", 8500: "Consul",
    8888: "HTTP-Alt", 8983: "Solr",
    9000: "PHP-FPM",  9042: "Cassandra",
    9090: "Prometheus", 9092: "Kafka",
    9100: "Printer-RAW",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    9418: "Git",
    9999: "Admin",
    10000: "Webmin",
    11211: "Memcached",
    15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 27018: "MongoDB-Shard",
    50000: "DB2", 50070: "Hadoop-HDFS",
    61616: "ActiveMQ-OpenWire",
}

TLS_PORTS: frozenset[int] = frozenset({443, 8443, 993, 995})

PROBES: dict[int, bytes | None] = {
    21: None, 22: None, 23: None,
    25:   b"EHLO scanner\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    110:  b"CAPA\r\n",
    143:  b"A001 CAPABILITY\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    587:  b"EHLO scanner\r\n",
    993:  b"A001 CAPABILITY\r\n",
    995:  b"CAPA\r\n",
    3306: None,
    5432: None,
    6379: b"PING\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    8008: b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: \r\n\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: \r\n\r\n",
}


def _grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    try:
        sock.settimeout(min(timeout, 2.0))
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError:
                return ""
        probe = PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)
        raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        return lines[0][:120] if lines else ""
    except OSError:
        return ""


def probe(host: str, port: int, timeout: float) -> tuple[int, str, str] | None:
    """Return (port, service, banner) if open, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        banner = _grab_banner(sock, host, port, timeout)
        return (port, SERVICES.get(port, ""), banner)
    except OSError:
        return None
    finally:
        sock.close()


def parse_ports(spec: str) -> list[int]:
    """Parse '1-1024', '80,443', or '22,100-200' into a sorted unique list."""
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"port range '{part}' out of bounds (1-65535)")
            out.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"port {p} out of bounds (1-65535)")
            out.add(p)
    if not out:
        raise ValueError("no ports specified")
    return sorted(out)


def resolve_host(target: str) -> str:
    return socket.gethostbyname(target)


def scan_stream(
    host: str,
    ports: Iterable[int],
    timeout: float,
    num_threads: int,
    *,
    on_open:     Callable[[int, str, str], None],
    on_progress: Callable[[int, int], None],   # (done, total)
    should_stop: Callable[[], bool],
) -> None:
    """Drive a threaded scan, invoking callbacks as results stream in."""
    port_list = list(ports)
    total = len(port_list)
    if total == 0:
        return

    port_q: queue.Queue[int] = queue.Queue()
    for p in port_list:
        port_q.put(p)

    done = 0
    state_lock = threading.Lock()

    def worker():
        nonlocal done
        while not should_stop():
            try:
                port = port_q.get_nowait()
            except queue.Empty:
                return
            try:
                result = probe(host, port, timeout)
            except Exception:
                result = None
            if result is not None:
                p, service, banner = result
                try:
                    on_open(p, service, banner)
                except Exception:
                    pass
            with state_lock:
                done += 1
                snap = done
            try:
                on_progress(snap, total)
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(num_threads, total))]
    for t in threads: t.start()
    for t in threads: t.join()
