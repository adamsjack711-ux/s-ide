# OWASP Juice Shop — modern JS-based vulnerable web app covering the
# full OWASP Top 10 with a built-in score tracker.
#
# Why we wrap the upstream image instead of building from source:
#
# Juice Shop v16's TypeScript devDeps drift faster than its pinned `tsc`
# can parse: `@types/babel__traverse` and `@types/lodash` use syntax
# (optional / `?` type modifier) that the older tsc rejects with TS1005.
# Bumping TypeScript in turn cascades into Angular CLI peer-dep refusals.
# Building from source on Apple Silicon also hits libxmljs2 native-binding
# breakage on Node ≥ 22 — Juice Shop is tested against Node 20.
#
# The upstream image is published at a stable tag, ships with build
# artifacts, runs as user 65532 on Node 20, and is exactly what their CI
# tests against. We stay reproducible by pinning the tag.

FROM bkimminich/juice-shop:v16.0.0

# Image exposes 3000 already and CMD ["npm", "start"] is set upstream.
