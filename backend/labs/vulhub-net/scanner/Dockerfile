# Scanner sidecar — joins the vulhub-net bridge so the HackingPal backend
# can reach internal IPs from macOS, where Docker Desktop hides the bridge.
#
# Image is intentionally small: just the tools that show up in the sidecar
# command whitelist (nmap, smbclient, curl, dig, nikto).

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        smbclient \
        curl \
        dnsutils \
        netcat-openbsd \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Sidecar idles; the backend execs commands into it on demand.
CMD ["sleep", "infinity"]
