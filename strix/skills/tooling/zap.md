---
name: zap
description: OWASP ZAP automated vulnerability scanner — workflow, alert interpretation, and integration with other Strix tools
---

# OWASP ZAP — Automated Vulnerability Scanner

ZAP (Zed Attack Proxy) runs as a dedicated Docker container (`zaproxy/zap-stable`) alongside the Strix sandbox. Use it for automated vulnerability detection across a broad attack surface, then validate findings manually.

## When to Use ZAP

- After completing reconnaissance and attack surface mapping
- For broad automated coverage before targeted manual testing
- Best at: reflected/stored XSS, injection patterns, missing security headers, authentication issues, path traversal, insecure configurations
- Complements manual testing — always validate High/Medium findings before reporting

## Standard Scan Workflow

```
Phase 1: Spider (discover attack surface)
  → zap_action action=spider target=https://app.com
  → Poll: zap_action action=status  (repeat until spider progress=100)

Phase 2: AJAX Spider (for SPAs — React/Angular/Vue)
  → zap_action action=ajax_spider target=https://app.com
  → Poll: zap_action action=status  (repeat until ajax_spider_running=false)
  → AJAX spider can take 2-5 minutes for large SPAs

Phase 3: Active Scan (run vulnerability tests)
  → zap_action action=active_scan target=https://app.com
  → Poll: zap_action action=status  (repeat until active scan progress=100)
  → Active scanning takes 5-30 min depending on app size

Phase 4: Retrieve findings
  → zap_action action=alerts max_alerts=100
```

**Polling frequency**: Check status every 30-60 seconds — don't spam it. Use `wait` or delay between status checks.

## Authenticated Scanning

If `PRE-CONFIGURED AUTHENTICATION` is active (Bearer token in browser), ZAP's spider and active scanner will NOT automatically use that token — ZAP has its own session.

**Workaround using the proxy tool:**
1. Configure Caido proxy to forward traffic to ZAP (chain proxies)
2. OR use ZAP's spider results as a URL list, then test endpoints manually via the proxy tool with the auth token

For authenticated ZAP scanning, use the terminal tool:
```bash
# Add auth header to ZAP's HTTP sessions
curl -s "http://$STRIX_ZAP_API_URL_INTERNAL/JSON/httpSessions/action/createEmptySession/?apikey=$STRIX_ZAP_API_KEY&site=https://app.com&session=auth"

# Set request header for ZAP session
curl -s "http://$STRIX_ZAP_API_URL_INTERNAL/JSON/replacer/action/addRule/?apikey=$STRIX_ZAP_API_KEY&description=AuthHeader&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=Bearer+TOKEN"
```

## Alert Severity Interpretation

| ZAP Risk | Action |
|---|---|
| **High** | Validate manually with PoC — very likely real, report if confirmed |
| **Medium** | Validate with browser or proxy tool — often real but context-dependent |
| **Low** | Review as part of hardening recommendations |
| **Informational** | Skip unless relevant (missing headers, version disclosure) |

**Common false positives:**
- "Absence of Anti-CSRF Tokens" — check if the app uses SameSite cookies instead
- "X-Content-Type-Options Header Missing" — legitimate finding but Low priority
- "Application Error Disclosure" — validate that the error reveals useful info
- SQL Injection on search forms — ZAP uses simple patterns; confirm with sqlmap

## ZAP + Other Tools Integration

ZAP findings guide follow-up testing:

```
ZAP finds XSS candidate → manual confirmation with browser_action execute_js
ZAP finds SQLi candidate → confirm with sqlmap via terminal_execute
ZAP finds path traversal → test deeper with custom payloads via send_request
ZAP finds auth issues  → load authentication_jwt skill for deeper testing
ZAP finds CORS headers → load cors_misconfiguration skill for full CORS testing
```

## Key ZAP Limitations

- Cannot test IDOR (requires semantic understanding of IDs)
- Cannot test business logic flaws
- Cannot test race conditions
- Limited on GraphQL (no deep introspection-based testing)
- AJAX spider may miss pages behind complex authentication flows
- Active scan can generate noise — use scope carefully

## Scope Safety

ZAP only scans the URL you provide and pages it discovers from that starting point. The Strix scope enforcement also blocks ZAP from scanning out-of-scope URLs via the `send_request` tool — however, ZAP's internal HTTP client is not subject to the same scope check. **Always start ZAP with an in-scope URL.** The authorized target list is visible in the system prompt.
