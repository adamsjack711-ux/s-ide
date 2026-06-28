# Apache Struts2 RCE — CVE-2017-5638
#
# The Jakarta multipart parser evaluates an OGNL expression supplied in
# the Content-Type header during a file upload — unauthenticated RCE,
# the bug behind the Equifax breach.
#
# We wrap piesecurity's canonical training image — ships the Struts2
# showcase app preinstalled at /struts2-showcase/. Internal port 8080,
# published on host 8089.

FROM piesecurity/apache-struts2-cve-2017-5638:latest

EXPOSE 8080
