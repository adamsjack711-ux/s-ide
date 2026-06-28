"""WiFi Integrity — single REST report.

Runs a battery of subprocess checks (SSID, security tier, gateway MAC,
DNS hijack) and returns a structured report. On macOS we use airport +
networksetup + scutil; on Linux we use iw + nmcli + ip + resolvectl.

The response shape is identical on both platforms — `findings` is a list of
sectioned severity-tagged rows the React side renders unchanged.
"""
from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from lib import hids_notify
from lib.auth import require_local_auth
from lib.platform_util import IS_DARWIN, require_unix

logger = logging.getLogger(__name__)

router = APIRouter(tags=["wifi"], dependencies=[Depends(require_local_auth)])

AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework"
           "/Versions/Current/Resources/airport")


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


class Finding(BaseModel):
    section: str           # "Connection" | "Gateway" | "DNS"
    label: str
    value: str = ""
    severity: str = "info" # "pass" | "info" | "warn" | "fail"
    note: str = ""


class WifiReport(BaseModel):
    ssid: str = ""
    bssid: str = ""
    security: str = ""
    signal_dbm: str = ""
    channel: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    dns_servers: list[str] = []
    findings: list[Finding] = []


# ── connection probes ────────────────────────────────────────────────────────

def _connection_mac(out: WifiReport) -> None:
    ns = _run(["networksetup", "-getairportnetwork", "en0"])
    if "Current Wi-Fi Network:" in ns:
        out.ssid = ns.split("Current Wi-Fi Network:")[-1].strip()

    airport_info = _run([AIRPORT, "-I"]) if Path(AIRPORT).exists() else ""
    if airport_info:
        for line in airport_info.splitlines():
            ls = line.strip()
            if ls.startswith("SSID") and "BSSID" not in ls and not out.ssid:
                out.ssid = ls.split(":")[-1].strip()
            elif ls.startswith("BSSID"):
                out.bssid = ls.split(":")[-1].strip()
            elif ls.startswith("agrCtlRSSI"):
                out.signal_dbm = ls.split(":")[-1].strip()
            elif ls.startswith("channel"):
                out.channel = ls.split(":")[-1].strip()
            elif ls.startswith("link auth"):
                out.security = ls.split(":")[-1].strip()


def _wifi_iface_linux() -> str:
    """Return the active WiFi interface name, or '' if none."""
    iw = shutil.which("iw")
    if iw:
        # `iw dev` prints blocks containing "Interface <name>" then "type managed".
        out = _run([iw, "dev"])
        iface = ""
        for line in out.splitlines():
            ls = line.strip()
            if ls.startswith("Interface "):
                iface = ls.split()[1]
            elif ls.startswith("type ") and "managed" in ls and iface:
                return iface
        if iface:
            return iface
    nmcli = shutil.which("nmcli")
    if nmcli:
        out = _run([nmcli, "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[1] == "wifi" and parts[2] == "connected":
                return parts[0]
    return ""


def _connection_linux(out: WifiReport) -> None:
    iface = _wifi_iface_linux()

    # nmcli is the most reliable single source on modern distros: SSID, BSSID,
    # signal, security, channel — all from one terse command. iw fills in
    # whatever nmcli leaves blank.
    nmcli = shutil.which("nmcli")
    if nmcli:
        # IN-USE marker is "*" for the current network.
        for col in ("IN-USE,SSID,BSSID,SIGNAL,CHAN,SECURITY",):
            row = _run([nmcli, "-t", "-f", col, "device", "wifi", "list"])
            for line in row.splitlines():
                # IN-USE field is empty or "*"; SSID can legitimately contain
                # colons but nmcli's -t escapes them. We split on unescaped ":".
                parts = re.split(r"(?<!\\):", line)
                parts = [p.replace("\\:", ":") for p in parts]
                if len(parts) < 6 or parts[0].strip() != "*":
                    continue
                out.ssid     = out.ssid     or parts[1]
                out.bssid    = out.bssid    or parts[2].lower()
                # nmcli signal is 0..100 %, not dBm — only set if iw didn't.
                if not out.signal_dbm and parts[3]:
                    out.signal_dbm = f"{parts[3]}% (nmcli)"
                out.channel  = out.channel  or parts[4]
                out.security = out.security or parts[5]
                break

    iw = shutil.which("iw")
    if iw and iface:
        link = _run([iw, "dev", iface, "link"])
        if "Not connected" not in link:
            for line in link.splitlines():
                ls = line.strip()
                if ls.startswith("Connected to ") and not out.bssid:
                    m = re.search(r"([0-9a-f:]{17})", ls)
                    if m:
                        out.bssid = m.group(1).lower()
                elif ls.startswith("SSID:") and not out.ssid:
                    out.ssid = ls.split(":", 1)[1].strip()
                elif ls.startswith("freq:") and not out.channel:
                    out.channel = ls.split(":", 1)[1].strip() + " MHz"
                elif ls.startswith("signal:"):
                    # signal: -47 dBm  → -47 dBm
                    out.signal_dbm = ls.split(":", 1)[1].strip()

    if not out.ssid:
        # iwgetid as last resort — returns the connected SSID (no security info).
        iwgetid = shutil.which("iwgetid")
        if iwgetid:
            out.ssid = _run([iwgetid, "-r"])


def _add_connection_findings(out: WifiReport, findings: list[Finding]) -> None:
    if out.ssid:
        findings.append(Finding(section="Connection", label="SSID",
                                value=out.ssid, severity="pass"))
    else:
        findings.append(Finding(section="Connection", label="SSID",
                                value="Not connected", severity="warn"))
    if out.bssid:
        findings.append(Finding(section="Connection", label="BSSID", value=out.bssid))
    if out.signal_dbm:
        # Mac airport prints just the number; Linux iw prints "-47 dBm".
        sig = out.signal_dbm if "dBm" in out.signal_dbm or "%" in out.signal_dbm \
              else f"{out.signal_dbm} dBm"
        findings.append(Finding(section="Connection", label="Signal", value=sig))
    if out.channel:
        findings.append(Finding(section="Connection", label="Channel", value=out.channel))
    if out.security:
        sec_upper = out.security.upper()
        if "WPA3" in sec_upper or "SAE" in sec_upper:
            findings.append(Finding(section="Connection", label="Security",
                                    value=f"{out.security}  ✓ Strong", severity="pass",
                                    note="WPA3 uses SAE handshake — resists brute force and protects past sessions."))
        elif "WPA2" in sec_upper:
            findings.append(Finding(section="Connection", label="Security",
                                    value=f"{out.security}  ✓ OK", severity="pass",
                                    note="WPA2 is secure but vulnerable to handshake capture if password is weak."))
        elif "WEP" in sec_upper:
            findings.append(Finding(section="Connection", label="Security",
                                    value=f"{out.security}  ✗ CRITICAL", severity="fail",
                                    note="WEP was broken in 2001 — crackable in seconds. All traffic readable."))
        elif "OPEN" in sec_upper or out.security in ("none", "--", ""):
            findings.append(Finding(section="Connection", label="Security",
                                    value="OPEN — No encryption  ✗ CRITICAL", severity="fail",
                                    note="Zero encryption. Anyone in range can capture all your traffic."))
        else:
            findings.append(Finding(section="Connection", label="Security", value=out.security))


# ── gateway / ARP ────────────────────────────────────────────────────────────

def _gateway_mac(out: WifiReport, findings: list[Finding]) -> None:
    route = _run(["route", "-n", "get", "default"])
    for line in route.splitlines():
        if "gateway:" in line:
            out.gateway_ip = line.split(":")[-1].strip()
            break

    if not out.gateway_ip:
        findings.append(Finding(section="Gateway", label="Gateway",
                                value="Could not detect", severity="warn"))
        return

    findings.append(Finding(section="Gateway", label="Gateway IP", value=out.gateway_ip))
    arp = _run(["arp", "-n", out.gateway_ip], timeout=3)
    m = re.search(r"at ([0-9a-f:]{17})", arp)
    if m:
        out.gateway_mac = m.group(1)
        findings.append(Finding(section="Gateway", label="Gateway MAC",
                                value=out.gateway_mac, severity="pass"))
    else:
        findings.append(Finding(section="Gateway", label="Gateway MAC",
                                value="(not in ARP cache — try again in a moment)",
                                severity="warn"))


def _gateway_linux(out: WifiReport, findings: list[Finding]) -> None:
    ip = shutil.which("ip")
    if ip:
        route = _run([ip, "route", "show", "default"])
        # "default via 192.168.1.1 dev wlp3s0 proto dhcp ..."
        m = re.search(r"default via (\S+)", route)
        if m:
            out.gateway_ip = m.group(1)

    if not out.gateway_ip:
        findings.append(Finding(section="Gateway", label="Gateway",
                                value="Could not detect", severity="warn"))
        return

    findings.append(Finding(section="Gateway", label="Gateway IP", value=out.gateway_ip))
    if ip:
        # ip neighbor show <gw>  →  "192.168.1.1 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        neigh = _run([ip, "neighbor", "show", out.gateway_ip], timeout=3)
        m = re.search(r"lladdr ([0-9a-f:]{17})", neigh)
        if m:
            out.gateway_mac = m.group(1)
            findings.append(Finding(section="Gateway", label="Gateway MAC",
                                    value=out.gateway_mac, severity="pass"))
        else:
            findings.append(Finding(section="Gateway", label="Gateway MAC",
                                    value="(not in neighbor cache — try again in a moment)",
                                    severity="warn"))


# ── DNS ──────────────────────────────────────────────────────────────────────

def _dns_mac(out: WifiReport) -> None:
    dns_out = _run(["networksetup", "-getdnsservers", "Wi-Fi"])
    if "There aren't any" in dns_out or not dns_out:
        scu = _run(["scutil", "--dns"])
        out.dns_servers = re.findall(r"nameserver\[0\]\s*:\s*(\S+)", scu)
    else:
        out.dns_servers = dns_out.splitlines()


def _dns_linux(out: WifiReport) -> None:
    rctl = shutil.which("resolvectl")
    if rctl:
        # `resolvectl status` lists "Current DNS Server: x" and "DNS Servers: a b c".
        s = _run([rctl, "status"])
        servers: list[str] = []
        for line in s.splitlines():
            ls = line.strip()
            if ls.startswith("DNS Servers:") or ls.startswith("Current DNS Server:"):
                for tok in ls.split(":", 1)[1].split():
                    if tok and tok not in servers:
                        servers.append(tok)
        if servers:
            out.dns_servers = servers
            return
    # Fallback: parse /etc/resolv.conf
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                out.dns_servers.append(m.group(1))
    except Exception:
        pass


def _add_dns_findings(out: WifiReport, findings: list[Finding]) -> None:
    if out.dns_servers:
        for s in out.dns_servers[:4]:
            findings.append(Finding(section="DNS", label="DNS Server", value=s))
    else:
        findings.append(Finding(section="DNS", label="DNS Servers",
                                value="None configured (DHCP default)", severity="warn"))

    # DNS hijack heuristic — compare local vs 8.8.8.8 resolution.
    nslookup = shutil.which("nslookup")
    for domain in ("google.com", "cloudflare.com"):
        try:
            local = socket.gethostbyname(domain)
        except Exception:
            continue
        trusted: list[str] = []
        if nslookup:
            nsl = _run([nslookup, domain, "8.8.8.8"], timeout=5)
            capture = False
            for line in nsl.splitlines():
                if "Non-authoritative" in line or "Name:" in line:
                    capture = True
                if capture and line.strip().startswith("Address:"):
                    addr = line.split(":")[-1].strip()
                    if not addr.endswith("#53"):
                        trusted.append(addr)
        if trusted and local not in trusted:
            findings.append(Finding(
                section="DNS",
                label=f"DNS hijack ({domain})",
                value=f"local={local}  trusted={','.join(trusted[:3])}",
                severity="fail",
                note="Your DNS resolver returned a different IP than Google DNS — possible hijack/captive portal.",
            ))
        elif trusted:
            findings.append(Finding(
                section="DNS",
                label=f"Integrity ({domain})",
                value=f"matches public DNS · {local}", severity="pass",
            ))
        else:
            # Couldn't reach 8.8.8.8 — surface what we resolved locally without
            # claiming hijack-or-not.
            findings.append(Finding(
                section="DNS",
                label=f"Resolved ({domain})",
                value=f"local={local} (trusted-DNS comparison unavailable)",
                severity="info",
            ))


# ── public endpoint ──────────────────────────────────────────────────────────

@router.get("/wifi/report", response_model=WifiReport)
def report() -> WifiReport:
    require_unix("WiFi integrity probes use airport/networksetup/iw/nmcli — "
                 "Windows port not implemented yet.")
    findings: list[Finding] = []
    out = WifiReport()

    if IS_DARWIN:
        _connection_mac(out)
        _add_connection_findings(out, findings)
        _gateway_mac(out, findings)
        _dns_mac(out)
    else:
        _connection_linux(out)
        _add_connection_findings(out, findings)
        _gateway_linux(out, findings)
        _dns_linux(out)

    _add_dns_findings(out, findings)

    out.findings = findings
    for f in findings:
        if f.severity == "fail":
            hids_notify.notify_threadsafe(
                "critical", "wifi", f"WiFi: {f.label}",
                {"section": f.section, "value": f.value, "note": f.note,
                 "ssid": out.ssid, "bssid": out.bssid},
            )
    return out
