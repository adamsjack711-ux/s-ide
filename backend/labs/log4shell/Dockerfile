# Log4Shell — CVE-2021-44228
#
# Vulnerable Spring Boot app that logs the User-Agent header through
# log4j 2.14.x. Hit it with a JNDI payload in the header and it makes
# an outbound LDAP query.
#
# We wrap christophetd's canonical training image — the upstream is
# tagged stable, runs cleanly, and is what the public writeups use.
# The container exposes 8080 internally; we publish it on host 8087.

FROM ghcr.io/christophetd/log4shell-vulnerable-app:latest

EXPOSE 8080
