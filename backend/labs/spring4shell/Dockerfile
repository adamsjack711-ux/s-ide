# Spring4Shell — CVE-2022-22965
#
# Vulnerable Spring MVC + Tomcat stack. DataBinder walks user-supplied
# property paths into the ClassLoader and lets you write a JSP webshell
# into the webroot — /shell.jsp pops after a single crafted POST.
#
# We wrap vulfocus's prebuilt training image (a known vulhub-equivalent
# build for this CVE). Internal port 8080, published on host 8088.

FROM vulfocus/spring-core-rce-2022-03-29:latest

EXPOSE 8080
