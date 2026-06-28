#!/usr/bin/env bash
# Init MariaDB on first boot and grant root unrestricted network access.
set -e

DATA=/var/lib/mysql
SENTINEL="${DATA}/.mhp-init"

mkdir -p "$DATA" /run/mysqld && chown -R mysql:mysql "$DATA" /run/mysqld

if [ ! -f "$SENTINEL" ]; then
    if [ ! -d "${DATA}/mysql" ]; then
        mariadb-install-db --user=mysql --datadir="$DATA" >/dev/null
    fi

    mariadbd --user=mysql --datadir="$DATA" >/dev/null 2>&1 &
    PID=$!
    for i in {1..40}; do
        mariadb -e "SELECT 1" >/dev/null 2>&1 && break
        sleep 0.5
    done

    mariadb <<'SQL'
CREATE DATABASE IF NOT EXISTS appdb;
USE appdb;
CREATE TABLE IF NOT EXISTS creds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64),
  password VARCHAR(64)
);
INSERT INTO creds (username, password) VALUES
  ('admin','admin'),
  ('dev','dev'),
  ('msfadmin','msfadmin');

CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
ALTER USER 'root'@'localhost' IDENTIFIED BY '';
FLUSH PRIVILEGES;
SQL
    mariadb-admin shutdown
    wait $PID 2>/dev/null || true
    touch "$SENTINEL"
fi

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
