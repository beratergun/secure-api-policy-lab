# Secure API Policy Lab

## Overview
Secure API Policy Lab is a defensive local rule engine for reviewing bounded, recorded HTTP request/response metadata. It does not send requests or connect to a target.

## Problem
Recorded API metadata can be checked for basic policy inconsistencies before a reviewer considers deployment-specific controls. The rules should remain explainable and avoid turning the tool into a scanner.

## Architecture
`policy.py` contains pure metadata checks plus an in-memory sliding-window limiter simulation. `cli.py` validates bounded local JSON and prints deterministic results.

## Implemented Features
- HTTP method allowlist review
- Local absolute-path validation
- Request body-size bound
- Content-Type presence review
- Defensive wildcard-CORS signal for recorded authenticated metadata
- Monotonic in-memory sliding-window rate-limit simulation

## Run Locally
Python 3.12 or newer is sufficient; there are no third-party dependencies.

```bash
python cli.py examples/request.json
```

## Example
The included fixture is recorded metadata with a synthetic authorization marker. It demonstrates a CORS review finding without making a network request.

## Testing
```bash
python -m unittest discover -s tests -v
```

## Engineering Decisions
The evaluator normalizes request and response header names, rejects URL-shaped or protocol-relative paths, bounds body and header data, and keeps rate-limit simulation deterministic for recorded timestamps.

## Security / Privacy
No live HTTP requests, scanning, replay, SSRF, exploit execution, or credential use is performed. Examples use synthetic values and should not be replaced with production traffic containing secrets or personal data.

## Limitations
This is not a WAF, API gateway, vulnerability scanner, or authorization system. Real deployments require identity-aware controls, trusted proxy handling, durable distributed limits, audit logging, and formal schemas.

## Future Improvements
Potential extensions include OpenAPI-derived local rules, offline JSON Schema validation, signed policy bundles, and differential policy tests.

## License
MIT. See [LICENSE](LICENSE).
