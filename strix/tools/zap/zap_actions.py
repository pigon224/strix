"""
OWASP ZAP integration tool for Strix.

Connects to the zaproxy/zap-stable container started by docker_runtime.
Connection details are read from environment variables injected at container
startup: STRIX_ZAP_API_URL and STRIX_ZAP_API_KEY.

Deliberately minimal: only the actions needed to run a complete ZAP assessment.
"""

import os
from typing import Any, Literal

import httpx

from strix.tools.registry import register_tool


ZAP_ACTION = Literal[
    "spider",
    "ajax_spider",
    "active_scan",
    "status",
    "alerts",
    "stop",
]

_ZAP_STARTUP_WAIT_SECS = 90


def _zap_base() -> str:
    return os.environ.get("STRIX_ZAP_API_URL", "http://localhost:8090")


def _zap_key() -> str:
    return os.environ.get("STRIX_ZAP_API_KEY", "")


def _zap_get(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    """Make a GET request to the ZAP REST API."""
    base = _zap_base()
    key = _zap_key()
    url = f"{base}{path}"
    merged_params: dict[str, str] = {"apikey": key}
    if params:
        merged_params.update(params)
    try:
        with httpx.Client(trust_env=False, timeout=30) as client:
            resp = client.get(url, params=merged_params)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        return {"error": "ZAP API request timed out. ZAP may still be starting up (~90s)."}
    except httpx.ConnectError:
        return {
            "error": (
                f"Cannot connect to ZAP at {base}. "
                "ZAP may still be starting (allow ~90s after scan begins). "
                "Retry with zap_action status to check readiness."
            )
        }
    except httpx.HTTPStatusError as exc:
        return {"error": f"ZAP API error {exc.response.status_code}: {exc.response.text[:300]}"}


def _is_zap_available() -> bool:
    """Quick check whether ZAP's API is reachable."""
    if not os.environ.get("STRIX_ZAP_ENABLED"):
        return False
    result = _zap_get("/JSON/core/view/version/")
    return "error" not in result


def _zap_enabled_or_error() -> dict[str, str] | None:
    """Return an error dict if ZAP is not enabled, None if it is."""
    if not os.environ.get("STRIX_ZAP_ENABLED"):
        return {
            "error": (
                "ZAP is not enabled for this scan. "
                "The zaproxy/zap-stable image must be available on the host "
                "for ZAP to start automatically."
            )
        }
    return None


@register_tool(sandbox_execution=True, requires_zap_mode=True)
def zap_action(
    action: ZAP_ACTION,
    target: str | None = None,
    scan_id: str | None = None,
    max_alerts: int = 100,
    report_format: Literal["json", "html", "xml"] = "json",
) -> dict[str, Any]:
    """
    Interact with the OWASP ZAP vulnerability scanner running alongside this sandbox.

    Actions:
      spider        - Crawl target with ZAP's traditional spider (finds links/forms).
                      Requires: target (URL).
      ajax_spider   - Crawl JavaScript-heavy SPAs using a headless browser.
                      Requires: target (URL). Slower but finds more endpoints in SPAs.
      active_scan   - Run ZAP's active vulnerability scanner against a target.
                      Run spider first to give ZAP an attack surface to work with.
                      Requires: target (URL).
      status        - Get progress of all running spiders and active scans (0-100%).
      alerts        - Retrieve vulnerability findings from ZAP.
                      Optional: scan_id, max_alerts.
      stop          - Stop a running spider or active scan.
                      Requires: scan_id (returned by spider/active_scan).
    """
    err = _zap_enabled_or_error()
    if err:
        return err

    if action == "spider":
        if not target:
            return {"error": "target URL is required for spider action"}
        result = _zap_get("/JSON/spider/action/scan/", {"url": target, "recurse": "true"})
        if "error" in result:
            return result
        return {
            "scan_id": result.get("scan"),
            "message": (
                f"Spider started for {target}. "
                "Use zap_action status to monitor progress, "
                "then zap_action active_scan to run active tests."
            ),
        }

    if action == "ajax_spider":
        if not target:
            return {"error": "target URL is required for ajax_spider action"}
        result = _zap_get("/JSON/ajaxSpider/action/scan/", {"url": target})
        if "error" in result:
            return result
        return {
            "message": (
                f"AJAX spider started for {target}. "
                "Use zap_action status to monitor. "
                "AJAX spider has no scan_id — use status action to check 'running' field."
            )
        }

    if action == "active_scan":
        if not target:
            return {"error": "target URL is required for active_scan action"}
        result = _zap_get(
            "/JSON/ascan/action/scan/",
            {"url": target, "recurse": "true", "scanPolicyName": ""},
        )
        if "error" in result:
            return result
        return {
            "scan_id": result.get("scan"),
            "message": (
                f"Active scan started for {target}. "
                "Use zap_action status to monitor progress (100% = complete). "
                "Use zap_action alerts when done."
            ),
        }

    if action == "status":
        spider_scans = _zap_get("/JSON/spider/view/scans/")
        ascan_scans = _zap_get("/JSON/ascan/view/scans/")
        ajax_status = _zap_get("/JSON/ajaxSpider/view/status/")
        return {
            "spider_scans": spider_scans.get("scans", spider_scans),
            "active_scans": ascan_scans.get("scans", ascan_scans),
            "ajax_spider_running": ajax_status.get("status") == "running",
        }

    if action == "alerts":
        params: dict[str, str] = {"start": "0", "count": str(max_alerts)}
        if scan_id:
            params["scanId"] = scan_id
        result = _zap_get("/JSON/core/view/alerts/", params)
        alerts = result.get("alerts", result)
        # Summarise each alert to avoid bloating context
        if isinstance(alerts, list):
            summarised = [
                {
                    "risk": a.get("risk"),
                    "name": a.get("name"),
                    "url": a.get("url"),
                    "param": a.get("param"),
                    "evidence": (a.get("evidence") or "")[:200],
                    "description": (a.get("description") or "")[:300],
                    "solution": (a.get("solution") or "")[:200],
                    "cweid": a.get("cweid"),
                    "wascid": a.get("wascid"),
                }
                for a in alerts
            ]
            return {
                "total": len(summarised),
                "alerts": summarised,
                "note": (
                    "Alerts are summarised. Risk levels: High, Medium, Low, Informational. "
                    "Validate High/Medium findings manually before reporting."
                ),
            }
        return result

    if action == "stop":
        results: dict[str, Any] = {}
        if scan_id:
            results["spider_stop"] = _zap_get(
                "/JSON/spider/action/stop/", {"scanId": scan_id}
            )
            results["ascan_stop"] = _zap_get(
                "/JSON/ascan/action/stop/", {"scanId": scan_id}
            )
        else:
            results["ajax_spider_stop"] = _zap_get("/JSON/ajaxSpider/action/stop/")
        return results

    return {"error": f"Unknown action: {action}"}
