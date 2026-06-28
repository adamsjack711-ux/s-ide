# DVWA — Damn Vulnerable Web Application
#
# Builds a fully self-contained image: php:8.2-apache + MariaDB + DVWA from
# upstream master. First boot seeds the DB; subsequent boots skip that.
#
# Default app credentials (set after DVWA "Setup" runs on first visit):
#   admin / password

FROM php:8.2-apache

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        mariadb-server \
        mariadb-client \
        supervisor \
        libgd-dev \
        libpng-dev \
        libjpeg-dev \
        zlib1g-dev \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-jpeg && \
    docker-php-ext-install mysqli pdo pdo_mysql gd

# DVWA's RFI module needs allow_url_include. We use the dev php.ini template
# (more verbose errors — fine for a training lab) and override the two flags.
RUN cp /usr/local/etc/php/php.ini-development /usr/local/etc/php/php.ini && \
    sed -i 's|^allow_url_include = .*|allow_url_include = On|'  /usr/local/etc/php/php.ini && \
    sed -i 's|^allow_url_fopen = .*|allow_url_fopen = On|'      /usr/local/etc/php/php.ini

# Clone DVWA into the Apache docroot. --depth=1 keeps the image small.
# Done from /tmp so we don't try to rm -rf the cwd.
WORKDIR /tmp
RUN git clone --depth=1 https://github.com/digininja/DVWA.git /tmp/dvwa-src && \
    rm -rf /var/www/html && \
    mv /tmp/dvwa-src /var/www/html && \
    rm -rf /var/www/html/.git && \
    chown -R www-data:www-data /var/www/html
WORKDIR /var/www/html

# Pre-bake the DVWA db config so the "Setup" page just works on first visit.
RUN cp /var/www/html/config/config.inc.php.dist /var/www/html/config/config.inc.php && \
    sed -i "s|'db_user'.*=.*'dvwa';|'db_user' ] = 'dvwa';|"        /var/www/html/config/config.inc.php && \
    sed -i "s|'db_password'.*=.*'p@ssw0rd';|'db_password' ] = 'dvwa';|" /var/www/html/config/config.inc.php

# Init + supervisord configs.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
