"""Per-tool setup-requirements registry.

Lists what each tool needs to run (binaries, API keys, sudoers, target
format, supported platforms, and what it produces). Surfaced in the UI
via the /tools/requirements router so users know up front what they
have to install/configure before clicking Run.

Coverage isn't exhaustive — every category is represented but pages
that work out of the box with just the FastAPI backend are intentionally
short on entries to keep this file maintainable. Add an entry whenever
a tool grows a new dependency.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from pydantic import BaseModel


class BinaryReq(BaseModel):
    name: str
    install_hint: str
    # Absolute fallback paths probed when the binary isn't on $PATH — e.g.
    # macOS `airport` lives at a system framework path that `which` won't find.
    paths: list[str] = []
    # Restrict the readiness probe to specific platforms. Empty = all.
    # Lets us declare per-platform alternatives (airport/netsh/iw) without
    # the cross-platform members showing up as "missing" on the host OS.
    platforms: list[str] = []


class ApiKeyReq(BaseModel):
    provider: str
    env_var: str | None = None
    keyring: str | None = None
    how_to: str


class SetupReq(BaseModel):
    binaries: list[BinaryReq] = []
    api_keys: list[ApiKeyReq] = []
    sudoers: bool = False
    sudoers_file: str | None = None
    platforms: list[str] = ["darwin", "linux", "win32"]
    network_required: bool = False
    docker_required: bool = False


class ToolRequirement(BaseModel):
    id: str
    name: str
    category: str
    router: str
    endpoints: list[str]
    target_format: str
    target_examples: list[str]
    setup: SetupReq
    expected_output: str
    notes: str | None = None


def _b(name: str, hint: str, *,
       paths: list[str] | None = None,
       platforms: list[str] | None = None) -> BinaryReq:
    return BinaryReq(name=name, install_hint=hint,
                     paths=paths or [], platforms=platforms or [])


_AIRPORT_PATH = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)

# Binaries on macOS/Linux frequently live under /usr/sbin or /sbin, which
# aren't on every shell's $PATH (notably under tmux/cron/electron-spawned
# subprocesses). Listing absolute fallbacks here lets `_binary_present`
# detect them even when `shutil.which` returns None.
_SBIN_PATHS = {
    "tcpdump":  ["/usr/sbin/tcpdump", "/sbin/tcpdump"],
    "arp":      ["/usr/sbin/arp", "/sbin/arp"],
    "ping":     ["/sbin/ping", "/bin/ping", "/usr/bin/ping"],
    "iw":       ["/usr/sbin/iw", "/sbin/iw"],
    "nft":      ["/usr/sbin/nft", "/sbin/nft"],
    "iptables": ["/usr/sbin/iptables", "/sbin/iptables"],
    "ip":       ["/usr/sbin/ip", "/sbin/ip"],
    "dig":      ["/usr/bin/dig", "/usr/local/bin/dig"],
    "whois":    ["/usr/bin/whois", "/usr/local/bin/whois"],
    "openssl":  ["/usr/bin/openssl", "/opt/homebrew/bin/openssl",
                 "/usr/local/opt/openssl/bin/openssl"],
}


def _k(provider: str, how_to: str, env_var: str | None = None,
       keyring: str | None = None) -> ApiKeyReq:
    return ApiKeyReq(provider=provider, env_var=env_var, keyring=keyring,
                     how_to=how_to)


def _hint(mac: str | None = None, linux: str | None = None,
          win: str | None = None) -> str:
    """Compose a one-line install hint that names the package manager per OS.

    install_hint is surfaced verbatim in the UI (Tools.tsx, ToolRequirements.tsx)
    without platform context, so each hint should call out every OS that needs
    a separate command. Pass None for OSes that don't apply.
    """
    bits: list[str] = []
    if mac:
        bits.append(f"macOS: {mac}")
    if linux:
        bits.append(f"Linux: {linux}")
    if win:
        bits.append(f"Windows: {win}")
    return " · ".join(bits) if bits else ""


_BREW = "brew install"

# fmt: off
TOOLS: list[ToolRequirement] = [
    # ── DISCOVERY ───────────────────────────────────────────────────────
    ToolRequirement(
        id="ip", name="IP Checker", category="DISCOVERY",
        router="routers/ip_checker.py", endpoints=["/ip/lookup"],
        target_format="ip", target_examples=["8.8.8.8", "1.1.1.1"],
        setup=SetupReq(network_required=True),
        expected_output="Geolocation, ASN, reverse DNS, abuse contact.",
    ),
    ToolRequirement(
        id="dns", name="DNS Recon", category="DISCOVERY",
        router="routers/dns_recon.py", endpoints=["/dns/recon"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(binaries=[_b("dig",
                                    _hint(mac=f"{_BREW} bind",
                                          linux="apt-get install dnsutils  (or yum install bind-utils)",
                                          win="install BIND tools from isc.org or use WSL"),
                                    paths=_SBIN_PATHS["dig"])],
                       network_required=True),
        expected_output="A / AAAA / NS / MX / TXT records + AXFR attempt.",
    ),
    ToolRequirement(
        id="whois", name="WHOIS · ASN", category="DISCOVERY",
        router="routers/whois.py", endpoints=["/whois/lookup"],
        target_format="domain", target_examples=["example.com", "8.8.8.0/24"],
        setup=SetupReq(binaries=[_b("whois",
                                    _hint(mac=f"{_BREW} whois",
                                          linux="apt-get install whois  (or yum install whois)",
                                          win="install Sysinternals whois.exe"),
                                    paths=_SBIN_PATHS["whois"])],
                       network_required=True),
        expected_output="Registrant, registrar, ASN, allocation history.",
    ),
    ToolRequirement(
        id="lan", name="LAN Scan", category="DISCOVERY",
        router="routers/lan_scan.py", endpoints=["/lan/scan"],
        target_format="ip-or-cidr", target_examples=["192.168.1.0/24"],
        setup=SetupReq(binaries=[_b("arp", "preinstalled on macOS/Linux",
                                    paths=_SBIN_PATHS["arp"])],
                       platforms=["darwin", "linux"]),
        expected_output="Live hosts on the local segment with hostname + MAC.",
    ),
    ToolRequirement(
        id="ping", name="Ping", category="DISCOVERY",
        router="routers/ping.py", endpoints=["/ping/run"],
        target_format="host", target_examples=["8.8.8.8", "example.com"],
        setup=SetupReq(binaries=[_b("ping", "system built-in",
                                    paths=_SBIN_PATHS["ping"])]),
        expected_output="ICMP round-trip times + packet loss.",
    ),
    ToolRequirement(
        id="localdisco", name="Local Discovery", category="DISCOVERY",
        router="routers/local_discovery.py", endpoints=["/local/disco"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["darwin", "linux"]),
        expected_output="LLMNR / NBNS / mDNS chatter visible on this host.",
    ),

    # ── RECON ───────────────────────────────────────────────────────────
    ToolRequirement(
        id="ports", name="Port Scanner", category="RECON",
        router="routers/port_scanner.py", endpoints=["/scan/ports", "/ws/scan"],
        target_format="ip-or-host", target_examples=["127.0.0.1", "scanme.nmap.org"],
        setup=SetupReq(),
        expected_output="Open TCP ports + service guess from banner.",
        notes="Pure-Python TCP connect scan — no extra deps.",
    ),
    ToolRequirement(
        id="nmap", name="Nmap", category="RECON",
        router="routers/nmap.py",
        endpoints=["/nmap/run", "/nmap/scripts", "/nmap/sudoers/install"],
        target_format="ip-or-host", target_examples=["127.0.0.1", "scanme.nmap.org"],
        setup=SetupReq(binaries=[_b("nmap",
                                    _hint(mac=f"{_BREW} nmap",
                                          linux="apt-get install nmap  (or yum install nmap)"))],
                       sudoers=True,
                       sudoers_file="/etc/sudoers.d/network-tools-nmap",
                       platforms=["darwin", "linux"]),
        expected_output="Service version, OS guess, NSE script output (612 scripts).",
        notes="SYN / OS / UDP scans need sudo — the page offers a one-click sudoers install.",
    ),
    ToolRequirement(
        id="audit", name="Network Audit", category="RECON",
        router="routers/audit.py", endpoints=["/audit/run"],
        target_format="ip-or-cidr", target_examples=["192.168.1.0/24"],
        setup=SetupReq(),
        expected_output="Risk-ranked summary of open ports with fix recommendations.",
    ),
    ToolRequirement(
        id="tls", name="TLS Auditor", category="RECON",
        router="routers/tls_audit.py", endpoints=["/tls/audit"],
        target_format="host", target_examples=["example.com", "github.com:443"],
        setup=SetupReq(binaries=[_b("openssl",
                                    _hint(mac=f"system built-in (or {_BREW} openssl for newer LibreSSL)",
                                          linux="usually preinstalled (apt-get install openssl)",
                                          win="install Win64 OpenSSL or use WSL"),
                                    paths=_SBIN_PATHS["openssl"])],
                       network_required=True),
        expected_output="TLS version, cipher suites, cert chain, expiry, HSTS.",
    ),
    ToolRequirement(
        id="fingerprint", name="Fingerprint", category="RECON",
        router="routers/fingerprint.py", endpoints=["/fingerprint/probe"],
        target_format="url", target_examples=["https://example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Server, framework, CDN, WAF signatures.",
    ),
    ToolRequirement(
        id="http", name="HTTP Probe", category="RECON",
        router="routers/http_probe.py", endpoints=["/http/probe"],
        target_format="url", target_examples=["https://example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Path enumeration + security-header analysis (SPA-aware).",
    ),
    ToolRequirement(
        id="tcpdump", name="TCPDump", category="RECON",
        router="routers/tcpdump.py",
        endpoints=["/tcpdump/start", "/tcpdump/stop", "/tcpdump/sudoers/install"],
        target_format="none", target_examples=["en0", "eth0"],
        setup=SetupReq(binaries=[_b("tcpdump",
                                    _hint(mac="preinstalled at /usr/sbin/tcpdump",
                                          linux="usually preinstalled (apt-get install tcpdump if missing)"),
                                    paths=_SBIN_PATHS["tcpdump"])],
                       sudoers=True,
                       sudoers_file="/etc/sudoers.d/network-tools-tcpdump",
                       platforms=["darwin", "linux"]),
        expected_output="Live packet capture, BPF filter, pcap export.",
        notes="Page offers a one-click sudoers install so tcpdump can open the interface without prompting.",
    ),

    # ── OSINT ───────────────────────────────────────────────────────────
    ToolRequirement(
        id="ct", name="CT Logs", category="OSINT",
        router="routers/ct_log.py", endpoints=["/ct/search"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Subdomains pulled from crt.sh certificate transparency logs.",
    ),
    ToolRequirement(
        id="email", name="Email Sec", category="OSINT",
        router="routers/email_security.py", endpoints=["/email/security"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(network_required=True),
        expected_output="SPF / DKIM / DMARC posture + reputation flags.",
    ),
    ToolRequirement(
        id="breach", name="Breach Lookup", category="OSINT",
        router="routers/breach.py", endpoints=["/breach/check"],
        target_format="email-or-domain", target_examples=["user@example.com"],
        setup=SetupReq(
            api_keys=[_k("HaveIBeenPwned",
                         "Get a key at haveibeenpwned.com/API/Key — paste in Settings.",
                         keyring="hibp_api_key")],
            network_required=True),
        expected_output="Known breaches the address/domain has appeared in.",
    ),
    ToolRequirement(
        id="shodanc", name="Shodan · Censys", category="OSINT",
        router="routers/shodan_censys.py",
        endpoints=["/shodan/host/{target}", "/shodan/search", "/censys/host"],
        target_format="ip-or-domain", target_examples=["8.8.8.8", "example.com"],
        setup=SetupReq(
            api_keys=[
                _k("Shodan", "Free key at shodan.io/account — Settings → Shodan.",
                   keyring="shodan_api_key"),
                _k("Censys", "Get API ID + secret at censys.io/account/api — Settings → Censys.",
                   keyring="censys_api_id"),
            ],
            network_required=True),
        expected_output="Open ports, services, banners as seen from the Internet.",
    ),
    ToolRequirement(
        id="ghleak", name="GitHub Leak Scan", category="OSINT",
        router="routers/github_leak.py", endpoints=["/github/leak"],
        target_format="domain-or-org", target_examples=["example.com", "octocat"],
        setup=SetupReq(
            api_keys=[_k("GitHub", "Create a fine-grained PAT (read:public_repo) at github.com/settings/tokens.",
                         keyring="github_pat", env_var="GITHUB_TOKEN")],
            network_required=True),
        expected_output="Leaked secrets in public repos matching the org/domain.",
    ),
    ToolRequirement(
        id="urlscan", name="URLScan", category="OSINT",
        router="routers/urlscan.py", endpoints=["/urlscan/lookup"],
        target_format="url", target_examples=["https://example.com"],
        setup=SetupReq(
            api_keys=[_k("urlscan.io", "Free key at urlscan.io/user/profile.",
                         keyring="urlscan_api_key")],
            network_required=True),
        expected_output="URL reputation, screenshot, IOCs from urlscan.io.",
    ),
    ToolRequirement(
        id="wayback", name="Wayback URLs", category="OSINT",
        router="routers/wayback.py", endpoints=["/wayback/urls"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Historical URLs from web.archive.org — surfaces forgotten endpoints.",
    ),

    # ── WEB RECON ───────────────────────────────────────────────────────
    ToolRequirement(
        id="subdom", name="Subdomain Enum", category="WEB RECON",
        router="routers/subdomain_enum.py", endpoints=["/subdomain/enum"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Live subdomains from passive sources + bruteforce.",
    ),
    ToolRequirement(
        id="cms", name="CMS / Stack", category="WEB RECON",
        router="routers/cms.py", endpoints=["/cms/fingerprint"],
        target_format="url", target_examples=["https://example.com"],
        setup=SetupReq(network_required=True),
        expected_output="CMS + framework + JS libs with versions and known CVE flags.",
    ),
    ToolRequirement(
        id="jwt", name="JWT", category="WEB RECON",
        router="routers/jwt_analyzer.py", endpoints=["/jwt/analyze"],
        target_format="jwt-token", target_examples=["eyJhbGciOiJIUzI1NiIs..."],
        setup=SetupReq(),
        expected_output="Header/payload decoded, alg flagged, weak-secret check.",
    ),

    # ── WEB EXPLOIT ─────────────────────────────────────────────────────
    ToolRequirement(
        id="xss", name="XSS", category="WEB EXPLOIT",
        router="routers/xss.py", endpoints=["/xss/scan", "/ws/xss"],
        target_format="url", target_examples=["https://example.com/search?q=test"],
        setup=SetupReq(network_required=True),
        expected_output="Reflected / stored / DOM XSS hits with PoC payloads.",
        notes="Active check — engagement mode + authorization required.",
    ),
    ToolRequirement(
        id="sqli", name="SQL Injection", category="WEB EXPLOIT",
        router="routers/sqli.py", endpoints=["/sqli/scan", "/ws/sqli"],
        target_format="url", target_examples=["https://example.com/item?id=1"],
        setup=SetupReq(network_required=True),
        expected_output="Injectable params, DBMS guess, blind vs union vector.",
        notes="Active check — engagement mode + authorization required.",
    ),

    # ── CLOUD ───────────────────────────────────────────────────────────
    ToolRequirement(
        id="aws", name="AWS Recon", category="CLOUD",
        router="routers/aws_recon.py",
        endpoints=["/aws/iam", "/aws/s3", "/aws/ec2", "/aws/lambda", "/aws/rds"],
        target_format="aws-profile", target_examples=["default", "myorg-prod"],
        setup=SetupReq(
            api_keys=[_k("AWS", "Run `aws configure` so boto3 finds ~/.aws/credentials.",
                         env_var="AWS_PROFILE")],
            network_required=True),
        expected_output="IAM, S3, EC2, Lambda, RDS inventory + risk flags.",
    ),
    ToolRequirement(
        id="azure", name="Azure Recon", category="CLOUD",
        router="routers/azure_recon.py", endpoints=["/azure/recon"],
        target_format="tenant-id", target_examples=["tenantid-or-subscription"],
        setup=SetupReq(
            api_keys=[_k("Azure", "Run `az login` so azure-mgmt sees creds.",
                         env_var="AZURE_SUBSCRIPTION_ID")],
            network_required=True),
        expected_output="Subscriptions, resource groups, storage, network exposure.",
    ),
    ToolRequirement(
        id="gcp", name="GCP Recon", category="CLOUD",
        router="routers/gcp_recon.py", endpoints=["/gcp/recon"],
        target_format="project-id", target_examples=["my-gcp-project"],
        setup=SetupReq(
            api_keys=[_k("GCP", "`gcloud auth application-default login` for ADC.",
                         env_var="GOOGLE_APPLICATION_CREDENTIALS")],
            network_required=True),
        expected_output="IAM, GCS, GCE, Cloud Functions inventory.",
    ),
    ToolRequirement(
        id="s3", name="S3 Bucket Scanner", category="CLOUD",
        router="routers/s3_scanner.py", endpoints=["/s3/scan"],
        target_format="domain-or-name", target_examples=["example.com", "acme"],
        setup=SetupReq(network_required=True),
        expected_output="Public S3 buckets matching name permutations.",
        notes="Anonymous probing — AWS creds optional but boost results.",
    ),

    # ── ACTIVE DIRECTORY ────────────────────────────────────────────────
    ToolRequirement(
        id="ldap", name="LDAP Enumerator", category="ACTIVE DIRECTORY",
        router="routers/ldap_enum.py", endpoints=["/ldap/enum"],
        target_format="ip-or-host", target_examples=["10.0.0.10", "dc01.corp.local"],
        setup=SetupReq(network_required=True),
        expected_output="Users, groups, OUs, password policy via LDAP bind.",
        notes="Anonymous + authenticated modes; ldap3 is bundled in Python deps.",
    ),
    ToolRequirement(
        id="smb", name="SMB Enumerator", category="ACTIVE DIRECTORY",
        router="routers/smb_enum.py", endpoints=["/smb/enum"],
        target_format="ip-or-host", target_examples=["10.0.0.10"],
        setup=SetupReq(
            binaries=[_b("smbclient",
                         _hint(mac=f"{_BREW} samba",
                               linux="apt-get install smbclient  (or yum install samba-client)"))],
            network_required=True, platforms=["darwin", "linux"]),
        expected_output="Shares, ACLs, null-session enumeration, signing status.",
    ),
    ToolRequirement(
        id="bloodhound", name="BloodHound Ingestor", category="ACTIVE DIRECTORY",
        router="routers/bloodhound_ingest.py", endpoints=["/bloodhound/ingest"],
        target_format="ip-or-host", target_examples=["dc01.corp.local"],
        setup=SetupReq(network_required=True, platforms=["darwin", "linux"]),
        expected_output="JSON dump compatible with BloodHound GUI.",
    ),

    # ── CRYPTO ──────────────────────────────────────────────────────────
    ToolRequirement(
        id="hash", name="Hash Cracker", category="CRYPTO",
        router="routers/hash_cracker.py", endpoints=["/hash/crack"],
        target_format="hash-string", target_examples=["$2a$10$...", "5f4dcc3b5aa765d61d8327deb882cf99"],
        setup=SetupReq(binaries=[_b("hashcat",
                                    _hint(mac=f"{_BREW} hashcat",
                                          linux="apt-get install hashcat",
                                          win="download from hashcat.net")),
                                 _b("john",
                                    _hint(mac=f"{_BREW} john",
                                          linux="apt-get install john",
                                          win="download from openwall.com/john"))]),
        expected_output="Plaintext if cracked; otherwise time estimate + best wordlist.",
        notes="Page falls back to the bundled rockyou wordlist if no GPU.",
    ),
    ToolRequirement(
        id="cvss", name="CVSS Calculator", category="CRYPTO",
        router="(frontend-only)", endpoints=[],
        target_format="none", target_examples=[],
        setup=SetupReq(),
        expected_output="CVSS v3.1 base/temporal/environmental score from vector.",
        notes="Pure frontend — no backend dependency.",
    ),

    # ── WIRELESS ────────────────────────────────────────────────────────
    ToolRequirement(
        id="wifiscan", name="WiFi Scan", category="WIRELESS",
        router="routers/wifi_scan.py", endpoints=["/wifi/scan"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("airport",
                          f"macOS built-in at {_AIRPORT_PATH}",
                          paths=[_AIRPORT_PATH],
                          platforms=["darwin"]),
                      _b("netsh", "Windows built-in",
                         platforms=["win32"]),
                      _b("iw", "apt-get install iw  (or yum install iw)",
                         paths=_SBIN_PATHS["iw"],
                         platforms=["linux"])],
        ),
        expected_output="Nearby SSIDs with BSSID, channel, signal, security.",
    ),
    ToolRequirement(
        id="wpacap", name="WPA Handshake / PMKID", category="WIRELESS",
        router="routers/wpa_capture.py", endpoints=["/wpa/capture"],
        target_format="bssid", target_examples=["AA:BB:CC:DD:EE:FF"],
        setup=SetupReq(
            binaries=[_b("aircrack-ng",
                          _hint(mac=f"{_BREW} aircrack-ng",
                                linux="apt-get install aircrack-ng")),
                      _b("hashcat",
                          _hint(mac=f"{_BREW} hashcat",
                                linux="apt-get install hashcat"))],
            platforms=["darwin"]),
        expected_output="EAPOL handshake / PMKID hash ready for hash_cracker.",
        notes="Requires a wifi adapter that supports monitor mode.",
    ),

    # ── MONITORING / FORENSICS ──────────────────────────────────────────
    ToolRequirement(
        id="ids", name="IDS", category="MONITORING",
        router="routers/ids.py", endpoints=["/ids/status", "/ids/events"],
        target_format="none", target_examples=[],
        setup=SetupReq(),
        expected_output="LSM-style file + network events from the host's watchdog.",
        notes="Backed by psutil + watchdog — no external setup.",
    ),
    ToolRequirement(
        id="audit-log", name="Audit Log", category="MONITORING",
        router="routers/audit_log.py", endpoints=["/audit_log/list"],
        target_format="none", target_examples=[],
        setup=SetupReq(),
        expected_output="Append-only record of tool runs (per engagement).",
    ),
    ToolRequirement(
        id="persistence", name="Persistence", category="FORENSICS",
        router="routers/persistence.py", endpoints=["/persistence/scan"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["darwin", "linux"]),
        expected_output="LaunchAgents / cron / systemd persistence enumeration.",
    ),
    ToolRequirement(
        id="processes", name="Processes", category="FORENSICS",
        router="routers/processes.py", endpoints=["/processes/list"],
        target_format="none", target_examples=[],
        setup=SetupReq(),
        expected_output="Process tree with parent / open files / sockets.",
    ),
    ToolRequirement(
        id="stego", name="Steganography", category="FORENSICS",
        router="routers/stego.py",
        endpoints=["/stego/embed", "/stego/extract", "/stego/analyze"],
        target_format="file-upload", target_examples=["image.png", "audio.wav"],
        setup=SetupReq(),
        expected_output="LSB embed/extract for PNG/BMP/WAV; chi-square detector for JPEG.",
    ),
    ToolRequirement(
        id="macos", name="macOS Posture", category="FORENSICS",
        router="routers/macos_posture.py", endpoints=["/macos/posture"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["darwin"]),
        expected_output="SIP, Gatekeeper, FileVault, XProtect, FW posture audit.",
    ),

    # ── UTILITIES ───────────────────────────────────────────────────────
    ToolRequirement(
        id="term", name="Terminal", category="UTILITIES",
        router="routers/terminal.py", endpoints=["/terminal/exec"],
        target_format="command", target_examples=["ls -la"],
        setup=SetupReq(),
        expected_output="One-shot command output (not a real PTY).",
        notes="Argv-only — `shell=True` is never used.",
    ),
    ToolRequirement(
        id="brew", name="Packages", category="UTILITIES",
        router="routers/brew.py", endpoints=["/brew/list", "/brew/install"],
        target_format="package-name", target_examples=["nmap", "wireshark"],
        setup=SetupReq(binaries=[_b("brew", "see brew.sh")],
                       platforms=["darwin"]),
        expected_output="Homebrew package list + install/upgrade actions.",
    ),
    ToolRequirement(
        id="triage", name="Target Triage", category="UTILITIES",
        router="routers/triage.py", endpoints=["/triage"],
        target_format="url-or-host", target_examples=["https://example.com"],
        setup=SetupReq(
            api_keys=[_k("Anthropic",
                         "Settings → Anthropic API key, or install the `claude` CLI on PATH.",
                         keyring="anthropic_api_key",
                         env_var="ANTHROPIC_API_KEY")],
            network_required=True),
        expected_output="Claude-tailored playbook for the target after a bounded passive probe.",
    ),

    # ── RECON (additional) ──────────────────────────────────────────────
    ToolRequirement(
        id="basic-check", name="Basic Check", category="RECON",
        router="routers/basic_check.py", endpoints=["/basic_check/run"],
        target_format="url-or-host", target_examples=["https://example.com"],
        setup=SetupReq(network_required=True),
        expected_output="~30s baseline: DNS + TLS + security headers + basic findings.",
        notes="Designed for someone testing their own app — bounded, passive, single endpoint.",
    ),

    # ── OSINT (additional) ──────────────────────────────────────────────
    ToolRequirement(
        id="dorking", name="Google Dorking", category="OSINT",
        router="routers/dorking.py",
        endpoints=["/dorking/categories", "/dorking/status", "/dorking/generate"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(
            api_keys=[_k("Google CSE",
                         "Optional — without keys, dorks are generated for manual paste.",
                         keyring="google_cse_api_key")],
            network_required=True),
        expected_output="Dork strings; optional CSE execution when keys are configured.",
    ),
    ToolRequirement(
        id="email-harvest", name="Email Harvester", category="OSINT",
        router="routers/email_harvest.py", endpoints=["/osint/emails/{domain}"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(
            api_keys=[_k("Hunter.io",
                         "Optional — augments crt.sh + page-scrape with Hunter results.",
                         keyring="hunter_api_key")],
            network_required=True),
        expected_output="Email addresses from CT logs + page scrape + optional Hunter API.",
    ),
    ToolRequirement(
        id="people", name="People Enum", category="OSINT",
        router="routers/people_enum.py", endpoints=["/people/status", "/people/enum"],
        target_format="domain", target_examples=["example.com"],
        setup=SetupReq(
            api_keys=[_k("Hunter.io",
                         "Optional — augments duckduckgo + crt.sh + hackertarget.",
                         keyring="hunter_api_key")],
            network_required=True),
        expected_output="People + email aggregator (theHarvester-style).",
    ),
    ToolRequirement(
        id="profile-finder", name="Profile Finder", category="OSINT",
        router="routers/profile_finder.py", endpoints=["/profile-finder/find"],
        target_format="company-name", target_examples=["Acme Corp"],
        setup=SetupReq(
            api_keys=[_k("Google CSE",
                         "Optional — without keys, falls back to scraping public search results.",
                         keyring="google_cse_api_key")],
            network_required=True),
        expected_output="Public profile candidates for the target company (LinkedIn-free, ToS-honest).",
    ),
    ToolRequirement(
        id="reverse-ip", name="Reverse IP", category="OSINT",
        router="routers/reverse_ip.py", endpoints=["/reverse-ip/{target}"],
        target_format="ip-or-host", target_examples=["1.1.1.1"],
        setup=SetupReq(network_required=True),
        expected_output="Other domains sharing the target IP (via HackerTarget free tier).",
        notes="HackerTarget rate-limits to ~50 queries/day on the free tier.",
    ),
    ToolRequirement(
        id="exploits", name="Exploit Lookup", category="OSINT",
        router="routers/exploits.py",
        endpoints=["/exploits/status", "/exploits/search",
                   "/exploits/{exploit_id}", "/exploits/search-from-scan"],
        target_format="cve-or-keyword",
        target_examples=["CVE-2024-12345", "apache 2.4.49"],
        setup=SetupReq(
            binaries=[_b("searchsploit",
                         "Optional — `brew install exploitdb` (Mac) or `apt install exploitdb` (Linux)")],
            network_required=True),
        expected_output="Exploit-DB entries; prefers local searchsploit, falls back to web API.",
        notes="searchsploit is optional but recommended — faster and works offline.",
    ),

    # ── WEB EXPLOIT (additional) ────────────────────────────────────────
    ToolRequirement(
        id="cmdi", name="Command Injection", category="WEB EXPLOIT",
        router="routers/cmdi.py", endpoints=["/ws/cmdi"],
        target_format="url-with-FUZZ",
        target_examples=["https://example.com/run?cmd=FUZZ"],
        setup=SetupReq(network_required=True),
        expected_output="Time-based + output-based command-injection vectors.",
        notes="Active check — engagement mode + authorization required.",
    ),
    ToolRequirement(
        id="lfi", name="LFI / Path Traversal", category="WEB EXPLOIT",
        router="routers/lfi.py", endpoints=["/ws/lfi"],
        target_format="url-with-FUZZ",
        target_examples=["https://example.com/file?p=FUZZ"],
        setup=SetupReq(network_required=True),
        expected_output="LFI hits with file-content signatures (e.g. /etc/passwd format).",
        notes="Active check — engagement mode + authorization required.",
    ),
    ToolRequirement(
        id="ssrf", name="SSRF", category="WEB EXPLOIT",
        router="routers/ssrf.py", endpoints=["/ws/ssrf"],
        target_format="url-with-FUZZ",
        target_examples=["https://example.com/proxy?url=FUZZ"],
        setup=SetupReq(network_required=True),
        expected_output="Internal-host reachability + cloud-metadata reflection through the sink.",
        notes="Active check — engagement mode + authorization required.",
    ),
    ToolRequirement(
        id="idor", name="IDOR", category="WEB EXPLOIT",
        router="routers/idor.py", endpoints=["/ws/idor"],
        target_format="url-with-FUZZ",
        target_examples=["https://example.com/api/orders/FUZZ"],
        setup=SetupReq(network_required=True),
        expected_output="Cross-account hits — iterates IDs across owner + attacker auth profiles.",
        notes="Active check — engagement mode + authorization required.",
    ),
    ToolRequirement(
        id="graphql", name="GraphQL Introspect", category="WEB EXPLOIT",
        router="routers/graphql.py", endpoints=["/graphql/introspect"],
        target_format="url", target_examples=["https://example.com/graphql"],
        setup=SetupReq(network_required=True),
        expected_output="Schema + types + queries + mutations + sensitive-field flags.",
        notes="Sends the standard introspection query — requires confirm=true.",
    ),
    ToolRequirement(
        id="takeover", name="Subdomain Takeover", category="WEB EXPLOIT",
        router="routers/takeover.py",
        endpoints=["/takeover/check/{fqdn}", "/ws/takeover-scan"],
        target_format="fqdn", target_examples=["foo.example.com"],
        setup=SetupReq(network_required=True),
        expected_output="Dangling CNAMEs pointing at takeover-prone services.",
    ),
    ToolRequirement(
        id="imds", name="IMDS Tester", category="WEB EXPLOIT",
        router="routers/imds.py", endpoints=["/ws/imds"],
        target_format="url-with-FUZZ",
        target_examples=["https://example.com/proxy?url=FUZZ"],
        setup=SetupReq(network_required=True),
        expected_output="Per-cloud IMDS endpoint reachability (AWS / Azure / GCP) via SSRF sink.",
    ),

    # ── ACTIVE DIRECTORY (additional) ───────────────────────────────────
    ToolRequirement(
        id="ad-spray", name="AD Password Spray", category="ACTIVE DIRECTORY",
        router="routers/ad_spray.py", endpoints=["/ws/ad-spray"],
        target_format="ip-or-host",
        target_examples=["10.0.0.10", "dc01.corp.local"],
        setup=SetupReq(network_required=True),
        expected_output="Successful (user, password) pairs; auto-backs-off at lockout threshold-1.",
        notes="Active check — confirm authorization. Reads domain lockoutThreshold first.",
    ),
    ToolRequirement(
        id="kerberos", name="Kerberoast / AS-REP", category="ACTIVE DIRECTORY",
        router="routers/kerberos_roast.py",
        endpoints=["/kerberoast/run", "/asrep/run"],
        target_format="ip-or-host", target_examples=["dc01.corp.local"],
        setup=SetupReq(network_required=True, platforms=["darwin", "linux"]),
        expected_output="Hashcat-format crackable material (mode 13100 / 18200).",
        notes="Uses Impacket — bundled in the backend Python deps.",
    ),
    ToolRequirement(
        id="lateral", name="Lateral Movement", category="ACTIVE DIRECTORY",
        router="routers/lateral.py",
        endpoints=["/lateral/load", "/lateral/status", "/lateral/clear",
                   "/lateral/path", "/lateral/techniques"],
        target_format="bloodhound-zip-or-json",
        target_examples=["20251101-1330_corp_users.json"],
        setup=SetupReq(),
        expected_output="Shortest attack paths from a starting principal to Domain Admins.",
        notes="In-memory graph parsed from BloodHound JSON; uploads capped at 200 MB.",
    ),

    # ── WIRELESS (additional) ───────────────────────────────────────────
    ToolRequirement(
        id="wifi", name="WiFi Integrity", category="WIRELESS",
        router="routers/wifi.py", endpoints=["/wifi/report"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("airport",
                          f"macOS built-in at {_AIRPORT_PATH}",
                          paths=[_AIRPORT_PATH],
                          platforms=["darwin"]),
                      _b("iw", "apt-get install iw  (or yum install iw)",
                         paths=_SBIN_PATHS["iw"],
                         platforms=["linux"])],
            platforms=["darwin", "linux"]),
        expected_output="SSID + security tier + gateway MAC + DNS hijack check.",
    ),
    ToolRequirement(
        id="evil-twin", name="Evil Twin", category="WIRELESS",
        router="routers/evil_twin.py", endpoints=["/ws/evil-twin"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("airport",
                          f"macOS built-in at {_AIRPORT_PATH}",
                          paths=[_AIRPORT_PATH],
                          platforms=["darwin"]),
                      _b("iw", "apt-get install iw  (or yum install iw)",
                         paths=_SBIN_PATHS["iw"],
                         platforms=["linux"])],
            platforms=["darwin", "linux"]),
        expected_output="Duplicate-SSID detections across multiple scans (channel / encryption / BSSID divergence).",
    ),
    ToolRequirement(
        id="bt", name="Bluetooth Recon", category="WIRELESS",
        router="routers/bt_recon.py", endpoints=["/bt/status", "/bt/devices"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("system_profiler", "macOS built-in",
                         platforms=["darwin"]),
                      _b("bluetoothctl", "apt-get install bluez",
                         platforms=["linux"])],
            platforms=["darwin", "linux"]),
        expected_output="Paired / connected / recently-seen Bluetooth devices.",
    ),

    # ── FORENSICS (additional) ──────────────────────────────────────────
    ToolRequirement(
        id="cred-harvest", name="Credential Harvest", category="FORENSICS",
        router="routers/cred_harvest.py", endpoints=["/cred-harvest/scan"],
        target_format="none", target_examples=[],
        setup=SetupReq(),
        expected_output="Plaintext credential exposure across ~/.aws, ~/.ssh, ~/.netrc, .env, etc.",
        notes="Read-only local audit — every secret stays on this machine and is redacted in the payload.",
    ),
    ToolRequirement(
        id="linux-posture", name="Linux Posture", category="FORENSICS",
        router="routers/linux_posture.py", endpoints=["/linux/posture"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["linux"]),
        expected_output="SELinux/AppArmor, firewall, systemd hardening, sudoers, kernel mitigations.",
    ),
    ToolRequirement(
        id="windows-posture", name="Windows Posture", category="FORENSICS",
        router="routers/windows_posture.py", endpoints=["/windows/posture"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["win32"]),
        expected_output="Defender, UAC, BitLocker, SMB, RDP, LSA-protection posture.",
    ),
    ToolRequirement(
        id="users-audit", name="User Audit", category="FORENSICS",
        router="routers/users_audit.py", endpoints=["/users/audit"],
        target_format="none", target_examples=[],
        setup=SetupReq(platforms=["linux"]),
        expected_output="/etc/passwd + /etc/shadow + sudo membership audit.",
    ),
    ToolRequirement(
        id="firewall-rules", name="Firewall Rules", category="FORENSICS",
        router="routers/firewall_rules.py", endpoints=["/firewall/rules"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("nft", "Linux nftables — preferred (apt-get install nftables)",
                         paths=_SBIN_PATHS["nft"],
                         platforms=["linux"]),
                      _b("iptables", "Linux iptables — fallback (apt-get install iptables)",
                         paths=_SBIN_PATHS["iptables"],
                         platforms=["linux"])],
            platforms=["linux"]),
        expected_output="Active nftables / iptables rule set.",
    ),
    ToolRequirement(
        id="systemd", name="Systemd Units", category="FORENSICS",
        router="routers/systemd_units.py",
        endpoints=["/systemd/units", "/systemd/unit/{name}",
                   "/systemd/journal/{name}"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("systemctl", "Linux systemd",
                         platforms=["linux"]),
                      _b("journalctl", "Linux systemd",
                         platforms=["linux"])],
            platforms=["linux"]),
        expected_output="systemd unit list + per-unit status + recent journal tail.",
    ),

    # ── RED TEAM ────────────────────────────────────────────────────────
    ToolRequirement(
        id="c2-beacon", name="C2 Beacon Simulator", category="RED TEAM",
        router="routers/c2_beacon.py",
        endpoints=["/c2/listener", "/c2/listeners", "/c2/listener/{lid}"],
        target_format="local-port", target_examples=["4444"],
        setup=SetupReq(network_required=True),
        expected_output="Local listener + copy-pasteable beacon commands (curl/wget/nc/powershell/bash).",
        notes="Egress-path testing — anything that reaches the listener is logged.",
    ),
    ToolRequirement(
        id="reverse-shell", name="Reverse Shell", category="RED TEAM",
        router="routers/reverse_shell.py",
        endpoints=["/reverse-shell/interfaces", "/reverse-shell/listeners",
                   "/reverse-shell/sessions", "/reverse-shell/payload-kinds"],
        target_format="bind-host-port", target_examples=["0.0.0.0:4444"],
        setup=SetupReq(network_required=True),
        expected_output="Listener + payload templates + interactive session WS.",
        notes="For authorized engagements — confirm authorization before binding a listener.",
    ),

    # ── TRAINING ────────────────────────────────────────────────────────
    ToolRequirement(
        id="labs", name="Training Labs", category="TRAINING",
        router="routers/labs.py",
        endpoints=["/labs", "/labs/catalog", "/labs/{id}/build",
                   "/labs/{id}/start", "/labs/{id}/stop",
                   "/labs/{id}/status", "/labs/preflight"],
        target_format="none", target_examples=[],
        setup=SetupReq(
            binaries=[_b("docker",
                         "Install Docker Desktop, OrbStack, or colima "
                         "(brew install colima docker)")],
            docker_required=True),
        expected_output=(
            "Docker-backed vulnerable apps (DVWA, Metasploitable, Juice "
            "Shop, vulhub-net) running locally; auto-registered as "
            "engagement targets."),
        notes=(
            "Spins up intentionally-vulnerable containers for practice — "
            "only run against the bundled lab targets, never anything "
            "you don't own."),
    ),
]
# fmt: on


def list_requirements() -> list[dict[str, Any]]:
    return [t.model_dump() for t in TOOLS]


def get_requirement(tool_id: str) -> ToolRequirement | None:
    for t in TOOLS:
        if t.id == tool_id:
            return t
    return None


def _has_keyring_entry(provider_key: str) -> bool:
    # Lazy-import keyring so the registry can load even when the macOS
    # Keychain backend can't be reached (CI, headless docker, etc.).
    try:
        import keyring  # type: ignore[import-untyped]
    except Exception:
        return False
    try:
        if keyring.get_password("HackingPal", provider_key):
            return True
        # Pre-rebrand fallback. Mirrors the read-fallback in
        # backend/routers/settings.py:keychain_get_named.
        return bool(keyring.get_password("MyHackingPal", provider_key))
    except Exception:
        return False


def _binary_present(b: BinaryReq) -> bool:
    if shutil.which(b.name) is not None:
        return True
    for p in b.paths:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return True
    return False


def check_readiness(req: ToolRequirement) -> dict[str, Any]:
    import sys
    plat = {"darwin": "darwin", "linux": "linux", "win32": "win32"}.get(
        sys.platform, sys.platform)

    # Skip binaries scoped to a different platform — they're not expected on
    # this OS and would otherwise always report missing.
    applicable_bins = [b for b in req.setup.binaries
                       if not b.platforms or plat in b.platforms]
    missing_bins = [b.name for b in applicable_bins if not _binary_present(b)]

    missing_keys: list[str] = []
    for k in req.setup.api_keys:
        env_ok = bool(k.env_var and os.environ.get(k.env_var))
        kr_ok = bool(k.keyring and _has_keyring_entry(k.keyring))
        if not (env_ok or kr_ok):
            missing_keys.append(k.provider)
    sudoers_missing = bool(req.setup.sudoers
                           and req.setup.sudoers_file
                           and not os.path.exists(req.setup.sudoers_file))
    platform_bad = plat not in req.setup.platforms

    return {
        "ready": not (missing_bins or missing_keys
                      or sudoers_missing or platform_bad),
        "missing": {
            "binaries": missing_bins,
            "api_keys": missing_keys,
            "sudoers": sudoers_missing,
            "platform": platform_bad,
        },
    }
