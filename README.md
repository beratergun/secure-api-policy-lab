# Secure API Policy Lab

Secure API Policy Lab is a defensive local rule engine for reviewing recorded HTTP request and response metadata.

It is not a scanner and it never sends traffic to a target. The idea is to take a bounded metadata record and run a small set of policy checks that are easy to explain and test.

## Current checks

The evaluator can report findings for:

- HTTP methods outside an allowlist
- Invalid or URL-shaped request paths
- Request bodies over a configured size
- Missing `Content-Type` on body-carrying methods
- Wildcard CORS in recorded authenticated-request metadata
- A local sliding-window rate-limit simulation

Findings contribute to a simple `ALLOW`, `REVIEW` or `BLOCK` decision.

## Why I built it

API security tooling often mixes policy validation with active traffic, proxies or scanning. I wanted a smaller project that stays on the defensive side and makes the policy logic visible in code.

Recorded inputs also make edge cases much easier to reproduce in tests.

## Run locally

Python 3.12 or newer is sufficient.

```bash
python cli.py examples/request.json
```

Tests:

```bash
python -m unittest discover -s tests -v
```

## Implementation details

Header names are normalized before evaluation. Request and response header objects are bounded, request paths are checked to ensure they are local absolute paths rather than URLs, and body size is measured in bytes.

The in-memory limiter uses a sliding window and rejects non-monotonic timestamps for the same key when recorded timestamps are supplied. This keeps the simulation predictable.

## Security scope

The repository performs no live HTTP requests, replay, SSRF testing, exploitation or credential use. Example data is synthetic and should remain that way.

## Limitations

This is not a WAF, API gateway, authorization service or vulnerability scanner. Real deployments need identity-aware authorization, trusted proxy handling, durable distributed rate limits, formal schemas and production audit logging.

## Possible next steps

Useful extensions could include OpenAPI-derived local checks, offline JSON Schema validation, signed policy bundles and differential policy tests.

## License

See [LICENSE](LICENSE).
