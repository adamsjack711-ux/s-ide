# Log4Shell — CVE-2021-44228
#
# Vulnerable Spring Boot app that logs the User-Agent header through
# log4j 2.14.x. Hit it with a JNDI payload in the header and it makes
# an outbound LDAP query.
#
# We wrap christophetd's canonical training image — the one the public
# writeups use. BUT that image ships an amd64-only Java 8/Alpine JVM, which
# hangs (100% CPU, no heap, never listens) under qemu emulation on Apple
# Silicon. The vulnerable artifact is the *jar* (platform-neutral Java
# bytecode bundling log4j 2.14.1), so we lift it out of the upstream image
# and run it on a NATIVE multi-arch JRE — fast, no emulation, vuln preserved.
#
# The COPY --from stage only extracts files; the amd64 image is never executed.

FROM ghcr.io/christophetd/log4shell-vulnerable-app:latest AS upstream

FROM eclipse-temurin:8-jre
COPY --from=upstream /app/spring-boot-application.jar /app/spring-boot-application.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/spring-boot-application.jar"]
