import math
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str


class SlidingWindowLimiter:
    def __init__(self, limit=10, window_seconds=60):
        if not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("limit must be 1..10000")
        if not isinstance(window_seconds, int) or not 1 <= window_seconds <= 86_400:
            raise ValueError("window_seconds must be 1..86400")
        self.limit = limit
        self.window = window_seconds
        self.events = defaultdict(deque)
        self.last_seen = {}

    def allow(self, key, now=None):
        normalized_key = str(key)[:200]
        if not normalized_key:
            raise ValueError("key required")
        timestamp = time.time() if now is None else float(now)
        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")
        if normalized_key in self.last_seen and timestamp < self.last_seen[normalized_key]:
            raise ValueError("timestamps must be monotonic per key")
        self.last_seen[normalized_key] = timestamp
        queue = self.events[normalized_key]
        while queue and queue[0] <= timestamp - self.window:
            queue.popleft()
        if len(queue) >= self.limit:
            return False
        queue.append(timestamp)
        return True


def _headers(value, field):
    if not isinstance(value, dict) or len(value) > 200:
        raise ValueError(f"{field} must be a bounded object")
    return {str(key).lower(): str(item)[:4_000] for key, item in value.items()}


def validate_record(record, allowed=("GET", "POST"), max_body_bytes=65_536):
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    if not isinstance(allowed, (list, tuple, set)) or not allowed:
        raise ValueError("allowed methods required")
    if not isinstance(max_body_bytes, int) or not 0 <= max_body_bytes <= 10_000_000:
        raise ValueError("invalid body bound")

    allowed_methods = {str(item).upper() for item in allowed}
    method = str(record.get("method", "")).upper()
    path = str(record.get("path", ""))[:2_000]
    headers = _headers(record.get("headers", {}), "headers")
    response_headers = _headers(record.get("response_headers", {}), "response_headers")
    body = record.get("body", "")
    if not isinstance(body, (str, bytes)):
        raise ValueError("body must be text or bytes")
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body

    findings = []
    if method not in allowed_methods:
        findings.append(Finding("method_not_allowed", "high", "Method outside allowlist."))
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or any(ord(character) < 32 for character in path)
    ):
        findings.append(Finding("invalid_path", "high", "Path must be a local absolute path, not a URL."))
    if len(body_bytes) > max_body_bytes:
        findings.append(Finding("body_too_large", "medium", "Body exceeds configured bound."))
    if method in {"POST", "PUT", "PATCH"} and "content-type" not in headers:
        findings.append(Finding("missing_content_type", "low", "Body-carrying method lacks Content-Type."))
    if (
        headers.get("origin")
        and response_headers.get("access-control-allow-origin") == "*"
        and headers.get("authorization")
    ):
        findings.append(
            Finding(
                "credentialed_wildcard_cors",
                "high",
                "Wildcard CORS observed with authenticated request metadata.",
            )
        )
    score = min(100, sum({"high": 40, "medium": 20, "low": 5}[finding.severity] for finding in findings))
    decision = "BLOCK" if score >= 60 else "REVIEW" if score >= 20 else "ALLOW"
    return {"decision": decision, "score": score, "findings": [asdict(finding) for finding in findings]}
