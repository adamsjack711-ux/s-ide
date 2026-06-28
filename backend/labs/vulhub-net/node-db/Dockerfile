# node-db (10.20.0.30) — MariaDB with root no password + Redis no auth.
# Both bound to all interfaces so the scanner sidecar can hit them.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        mariadb-server mariadb-client \
        redis-server \
        supervisor \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Open MariaDB to the bridge.
RUN sed -i 's|^bind-address.*|bind-address = 0.0.0.0|' \
    /etc/mysql/mariadb.conf.d/50-server.cnf

# Open Redis to the bridge with no auth (the classic "I forgot to firewall"
# anti-pattern).
RUN sed -i 's|^bind .*|bind 0.0.0.0|' /etc/redis/redis.conf && \
    sed -i 's|^protected-mode .*|protected-mode no|' /etc/redis/redis.conf

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh    /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 3306 6379
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
