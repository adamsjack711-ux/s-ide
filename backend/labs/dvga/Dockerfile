# Damn Vulnerable GraphQL Application
#
# Wraps the upstream image — DVGA's full build (Flask + Graphene + SQLite
# seed) is non-trivial and the maintainer publishes a working image.
#
# Vulnerabilities exposed:
#   - Introspection always enabled
#   - Stack traces on errors
#   - Batched queries (DoS / brute force)
#   - Deep nesting (resolver exhaustion)
#   - IDOR via opaque node IDs
#   - Command injection in the systemUpdate mutation
#   - SQL injection in a custom resolver
#
# Default port inside the container: 5013.

FROM dolevf/dvga:latest

EXPOSE 5013
# Upstream CMD already starts the Flask app on 5013, so we leave it alone.
