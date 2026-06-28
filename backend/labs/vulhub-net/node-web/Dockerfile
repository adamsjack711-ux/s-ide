# node-web (10.20.0.10) — Apache + PHP with a vulnerable login form.
# The scanner sidecar can probe port 80; users can pivot via cmdi.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 php libapache2-mod-php \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

RUN rm -f /var/www/html/index.html
COPY html/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
CMD ["bash", "-c", "rm -f /var/run/apache2/apache2.pid && /usr/sbin/apache2ctl -DFOREGROUND"]
