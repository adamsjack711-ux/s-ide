#!/usr/bin/env bash
# First-boot init for the Metasploitable-flavored lab container.
#   - Generate SSH host keys if missing.
#   - Initialize the MariaDB data dir and create the lab DB.
#   - Initialize Postfix queue dirs (postfix start refuses to run otherwise).
#   - Hand off to supervisord.
set -e

DATA_DIR=/var/lib/mysql
SENTINEL="${DATA_DIR}/.mhp-msf-init"

# ── SSH host keys ────────────────────────────────────────────────────────────
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "[msf] generating ssh host keys"
    ssh-keygen -A
fi
mkdir -p /run/sshd

# ── Postfix ──────────────────────────────────────────────────────────────────
# `newaliases` populates /etc/aliases.db; without it postfix start-fg complains.
newaliases >/dev/null 2>&1 || true

# Postfix needs its compat link refreshed under supervisord runtime.
postfix set-permissions >/dev/null 2>&1 || true

# ── MariaDB first-boot seed ──────────────────────────────────────────────────
mkdir -p "$DATA_DIR" /run/mysqld /var/run/vsftpd/empty
chown -R mysql:mysql "$DATA_DIR" /run/mysqld

if [ ! -f "$SENTINEL" ]; then
    echo "[msf] first boot — initializing MariaDB"

    if [ ! -d "${DATA_DIR}/mysql" ]; then
        mariadb-install-db --user=mysql --datadir="$DATA_DIR" >/dev/null
    fi

    mariadbd --user=mysql --datadir="$DATA_DIR" >/dev/null 2>&1 &
    MARIADB_PID=$!

    # Wait for the daemon to accept connections.
    for i in {1..40}; do
        if mariadb -e "SELECT 1" >/dev/null 2>&1; then break; fi
        sleep 0.5
    done

    # Set up the lab DB and intentionally leave root without a password.
    # `'root'@'%'` allows network logins; `'root'@'localhost'` for local.
    mariadb <<'SQL'
CREATE DATABASE IF NOT EXISTS labusers;
USE labusers;
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64),
    password VARCHAR(64)
);
INSERT IGNORE INTO users (username, password) VALUES
    ('admin','admin'),
    ('user','user'),
    ('msfadmin','msfadmin');

-- Open root for network access without a password (lab is intentionally insecure).
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
ALTER USER 'root'@'localhost' IDENTIFIED BY '';
FLUSH PRIVILEGES;
SQL

    mariadb-admin shutdown
    wait $MARIADB_PID 2>/dev/null || true

    touch "$SENTINEL"
    echo "[msf] MariaDB seeded"
fi

# ── Samba initial password (guest only, but smbd refuses to start without an
#    smbpasswd file in some configs) ──────────────────────────────────────────
mkdir -p /var/lib/samba/private
(echo "msfadmin"; echo "msfadmin") | smbpasswd -s -a msfadmin >/dev/null 2>&1 || true

# ── Hand off ─────────────────────────────────────────────────────────────────
echo "[msf] starting supervisord — services coming up shortly"
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
