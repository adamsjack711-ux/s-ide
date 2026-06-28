#!/usr/bin/env bash
# /var/run is tmpfs on Docker — services that expect specific run dirs need
# them recreated on every container start. vsftpd refuses to start without
# its chroot dir; samba's nmbd wants /var/run/samba.
set -e

mkdir -p /var/run/vsftpd/empty
mkdir -p /var/run/samba /var/lib/samba/private

# Bootstrap a guest-only smbpasswd file so smbd doesn't complain about the
# missing tdb on first boot.
(echo "msfadmin"; echo "msfadmin") | smbpasswd -s -a msfadmin >/dev/null 2>&1 || true

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
