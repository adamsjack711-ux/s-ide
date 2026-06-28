# Metasploitable-flavored multi-service lab
#
# Goal: a single container with the same "what does nmap see" surface as
# Metasploitable2 — lots of open ports, outdated banners, default creds,
# vulnerable webapp. Where building the actual CVE'd binary on a modern
# base would burn days (vsftpd 2.3.4, Samba 3.0.20, UnrealIRCd 3.2.8.1),
# we run a modern package with insecure config + a banner spoof + a
# separate emulated backdoor that matches the famous demo behavior.
#
# Services (host_port:container_port — see lib/labs.py port_map):
#
#   21    vsftpd        (anonymous on; banner spoofed to vsFTPd 2.3.4)
#   22    OpenSSH       (msfadmin:msfadmin, root:toor)
#   23    telnetd       (msfadmin:msfadmin)
#   25    postfix       (open relay-ish, banner spoofed)
#   80    apache + php  (vulnerable web pages — see web/)
#   139   smbd          (guest ok, null sessions; banner spoofed to Samba 3.0.20)
#   445   smbd          (same)
#   1524  bindshell     (socat → /bin/sh, no auth — emulates "ingreslock")
#   3306  mariadb       (root, no password; bound to 0.0.0.0)
#   3632  distccd       (allow=0.0.0.0/0)
#   6200  bindshell     (socat → /bin/sh, no auth — emulates vsftpd 2.3.4 backdoor)
#
# Default OS credentials:
#   msfadmin / msfadmin    (sudo-capable)
#   root     / toor
#
# Default app credentials (web /login.php):
#   admin / admin
#   user  / user

FROM debian:bullseye

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        # core utilities
        ca-certificates curl wget net-tools iproute2 procps tini sudo \
        # init / runtime
        supervisor socat \
        # services we'll start
        vsftpd \
        openssh-server \
        inetutils-telnetd xinetd \
        postfix \
        apache2 \
        php php-mysql libapache2-mod-php \
        samba samba-common-bin \
        mariadb-server mariadb-client \
        distcc \
        # toolchain (only kept for build-time; pruned at the end)
        gcc make \
        && rm -rf /var/lib/apt/lists/*

# ── Users ────────────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash -G sudo msfadmin && \
    echo "msfadmin:msfadmin" | chpasswd && \
    echo "root:toor"         | chpasswd && \
    echo "msfadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/msfadmin

# ── Configs ──────────────────────────────────────────────────────────────────
COPY configs/vsftpd.conf      /etc/vsftpd.conf
COPY configs/smb.conf         /etc/samba/smb.conf
COPY configs/sshd_config      /etc/ssh/sshd_config
COPY configs/postfix-main.cf  /etc/postfix/main.cf
COPY configs/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY configs/xinetd-telnet    /etc/xinetd.d/telnet
COPY configs/issue.net        /etc/issue.net

# Apache: enable PHP, point docroot at /var/www/html (default)
RUN rm -f /var/www/html/index.html

# Vulnerable web app — see web/README for details
COPY web/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html && \
    mkdir -p /var/www/html/uploads && \
    chown www-data:www-data /var/www/html/uploads && \
    chmod 777 /var/www/html/uploads

# SSH host keys generated lazily at first boot (entrypoint.sh).
RUN rm -f /etc/ssh/ssh_host_*

# MariaDB: open to 0.0.0.0 and disable mariadb's "fix this for me" hardening.
RUN sed -i 's|^bind-address.*|bind-address = 0.0.0.0|' /etc/mysql/mariadb.conf.d/50-server.cnf && \
    sed -i 's|^.*skip-external-locking.*|skip-external-locking = 0|' /etc/mysql/mariadb.conf.d/50-server.cnf || true

# Samba: pre-create the public share dir.
RUN mkdir -p /srv/samba/public && \
    chmod 0777 /srv/samba/public && \
    echo "Shared from Metasploitable. Drop files here." > /srv/samba/public/README.txt

# distccd config (the daemon also gets --allow/--listen on the command line,
# but /etc/default/distcc is read by some init scripts so we set it too).
RUN printf 'STARTDISTCC="true"\nALLOWEDNETS="0.0.0.0/0"\nLISTENER="0.0.0.0"\nNICE="10"\nJOBS=""\nZEROCONF="false"\n' \
    > /etc/default/distcc

# Tighten image by removing the compiler we used during build.
# Keep distcc for the daemon (distccd uses /usr/bin/distccd).
RUN apt-get purge -y gcc make && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Document the exposed ports. Actual publishing is done by `docker run -p ...`
# from lib/labs.py port_map.
EXPOSE 21 22 23 25 80 139 445 1524 3306 3632 6200

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
