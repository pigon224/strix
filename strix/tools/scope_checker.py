"""
Middleware-level scope enforcement for Strix tool execution.

Reads STRIX_AUTHORIZED_SCOPE_JSON from the container environment and validates
URLs before any tool executes a network request. This is enforced at the tool
layer — not just in the agent prompt — so out-of-scope requests are blocked
regardless of what the LLM decides to do.
"""

import json
import os
from urllib.parse import urlparse


def _get_authorized_targets() -> list[dict[str, str]]:
    """Load authorized targets from container environment variable."""
    raw = os.environ.get("STRIX_AUTHORIZED_SCOPE_JSON", "")
    if not raw:
        return []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []


def _extract_hostname(url: str) -> str | None:
    """Extract the hostname from a URL or plain domain string."""
    url = url.strip()
    if not url:
        return None

    # Add scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://", "ftp://", "ws://", "wss://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname  # lowercase, strips port
        return host if host else None
    except Exception:  # noqa: BLE001
        return None


def _is_hostname_in_scope(hostname: str, targets: list[dict[str, str]]) -> bool:
    """
    Return True if the hostname is covered by any authorized target.

    Scope rules:
    - web_application target "https://example.com":
        - "example.com" → in scope
        - "sub.example.com" → in scope (subdomain)
        - "example.website.com" → OUT OF SCOPE (different domain)
        - "notexample.com" → OUT OF SCOPE
    - ip_address target "192.168.1.1":
        - exact match only
    - Allow STRIX_SCOPE_STRICT_DOMAINS=true to block subdomains too
    """
    strict = os.environ.get("STRIX_SCOPE_STRICT_DOMAINS", "").lower() == "true"

    for target in targets:
        target_type = target.get("type", "")
        value = target.get("value", "")

        if target_type in ("web_application", "repository"):
            target_host = _extract_hostname(value)
            if not target_host:
                continue

            if hostname == target_host:
                return True

            if not strict and hostname.endswith("." + target_host):
                # Subdomain of authorized target
                return True

        elif target_type == "ip_address":
            # IP addresses: exact match only
            if hostname == value.strip():
                return True

    return False


def is_url_in_scope(url: str) -> bool:
    """
    Returns True if the URL's hostname is within authorized scope.
    Returns True if no scope is configured (backward compatibility — scope is
    only enforced when STRIX_AUTHORIZED_SCOPE_JSON is set by docker_runtime).
    """
    targets = _get_authorized_targets()
    if not targets:
        return True  # No scope configured — no restriction

    hostname = _extract_hostname(url)
    if hostname is None:
        return True  # Can't parse URL — let it through (fail-open for edge cases)

    # Always allow localhost / 127.x / internal addresses for white-box testing
    if hostname in ("localhost", "127.0.0.1", "::1") or hostname.startswith("192.168."):
        return True

    # Allow the Docker host gateway (used for local white-box targets)
    host_gateway = os.environ.get("HOST_GATEWAY", "host.docker.internal")
    if hostname == host_gateway:
        return True

    return _is_hostname_in_scope(hostname, targets)


def scope_error(url: str) -> dict[str, str]:
    """Return a standardized out-of-scope error dict for tool responses."""
    hostname = _extract_hostname(url) or url
    targets = _get_authorized_targets()
    authorized = [t.get("value", "") for t in targets]
    return {
        "error": "OUT_OF_SCOPE",
        "message": (
            f"Blocked: '{hostname}' is not in the authorized scope. "
            f"Authorized targets: {', '.join(authorized)}. "
            "Do not attempt to test assets outside the authorized scope."
        ),
        "blocked_url": url,
        "authorized_targets": authorized,
    }
