#!/usr/bin/env bash
# First-boot init for the DVWA lab container:
#   1. Bootstrap the MariaDB data dir if it's empty (first run only).
#   2. Create the `dvwa` database + user.
#   3. Hand off to supervisord, which keeps mariadb + apache running.
set -e

DATA_DIR=/var/lib/mysql
SENTINEL="${DATA_DIR}/.mhp-dvwa-init"

# Both data dir and the socket dir must exist + be owned by mysql before
# we start mariadbd. The socket dir is tmpfs on Docker, so we recreate it
# on every container start, not just first-boot.
mkdir -p "$DATA_DIR" /run/mysqld
chown -R mysql:mysql "$DATA_DIR" /run/mysqld

if [ ! -f "$SENTINEL" ]; then
    echo "[dvwa] first boot — initializing MariaDB..."

    if [ ! -d "${DATA_DIR}/mysql" ]; then
        mariadb-install-db --user=mysql --datadir="$DATA_DIR" >/dev/null
    fi

    mariadbd --user=mysql --datadir="$DATA_DIR" &
    MARIADB_PID=$!

    # Wait for the daemon to accept connections.
    for i in {1..40}; do
        if mariadb -e "SELECT 1" >/dev/null 2>&1; then break; fi
        sleep 0.5
    done

    mariadb <<'SQL'
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
SQL

    mariadb-admin shutdown
    wait $MARIADB_PID 2>/dev/null || true

    touch "$SENTINEL"
    echo "[dvwa] MariaDB initialized."
fi

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
