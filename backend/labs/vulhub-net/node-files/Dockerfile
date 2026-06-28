# node-files (10.20.0.20) — vsftpd (anonymous) + Samba (guest shares).
# Internal-only; reachable from the scanner sidecar and from node-web.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        vsftpd samba samba-common-bin supervisor \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

COPY configs/vsftpd.conf      /etc/vsftpd.conf
COPY configs/smb.conf         /etc/samba/smb.conf
COPY configs/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY share/                   /srv/samba/public/

RUN mkdir -p /srv/samba/public && chmod 0777 /srv/samba/public

# /var/run is tmpfs on Docker — create vsftpd's chroot dir on every start
# via an entrypoint shim. Same for samba's lock/run dirs.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 21 139 445
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
