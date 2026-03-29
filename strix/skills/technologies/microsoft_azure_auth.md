---
name: microsoft-azure-auth
description: Azure AD / Entra ID attack patterns including nOAuth, audience confusion, multi-tenant issuer bypass, PRT injection, OIDC misconfigurations, and scope validation bypass
---

# Microsoft Azure AD / Entra ID Security Testing

## Attack Surface

- OAuth2 / OIDC flows with Azure AD (Entra ID) as the identity provider
- Microsoft Identity Platform v1 (`login.microsoftonline.com/{tenant}/oauth2/`) and v2 (`/oauth2/v2.0/`) endpoints
- Enterprise application registrations, service principals, managed identities
- Multi-tenant vs single-tenant application configurations
- Conditional Access policies, MFA enforcement, and PRT-based SSO
- Microsoft Graph API authorization and scope enforcement

## Reconnaissance

### Detecting Azure AD Usage

Indicators in browser navigation and source:
- Redirect to `login.microsoftonline.com` or `login.microsoft.com`
- OIDC discovery endpoint: `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration`
- JWT `iss` claim contains `sts.windows.net` or `login.microsoftonline.com`
- `tid` (tenant ID) claim in decoded JWT — a GUID identifying the Azure tenant
- `appid` / `azp` (client ID) claim in decoded JWT — identifies the registered application

Indicators in JS bundles:
```bash
# MSAL library detection
grep -iE 'PublicClientApplication|@azure/msal|msal-browser|clientId.*tenantId|authority.*microsoftonline' /workspace/bundle.js

# Extract OAuth config (client ID, tenant, redirect URI, scopes)
grep -oE '"clientId"\s*:\s*"[a-f0-9-]{36}"' /workspace/bundle.js
grep -oE '"authority"\s*:\s*"https://login\.microsoftonline\.com/[^"]*"' /workspace/bundle.js
grep -oE '"redirectUri"\s*:\s*"[^"]*"' /workspace/bundle.js
grep -oE '"scopes"\s*:\s*\[[^\]]*\]' /workspace/bundle.js
```

### JWT Token Analysis

Harvest Bearer tokens from network capture:
```python
import json, base64

# Decode any captured Bearer token (no signature verification needed)
def decode_jwt(token):
    parts = token.split('.')
    if len(parts) < 2:
        return {}
    padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}
```

Key claims to inspect:
- `iss` — issuer: should be `https://login.microsoftonline.com/{tenant-id}/v2.0` (not `/common/`)
- `aud` — audience: should exactly match the target API's application URI or client ID
- `tid` — tenant ID: the Azure tenant that issued the token
- `oid` — object ID: unique, immutable user identifier (use this, not `email`)
- `sub` — subject: pairwise user identifier per application
- `email` / `upn` — mutable, user-controllable in some configurations (nOAuth vector)
- `scp` — delegated scopes (e.g., `User.Read openid profile`)
- `roles` — application roles assigned to the user
- `appid` / `azp` — the application that requested the token
- `exp` — expiry (Unix timestamp); tokens typically live 1 hour

Tool-based inspection:
```bash
jwt_tool -t <access_token> -jd
```

## Key Vulnerabilities

### nOAuth — Email Claim Trust (Critical)

**Description:** Applications that use the `email` claim from Azure AD tokens as a unique user identifier are vulnerable. The `email` attribute is mutable and can be set arbitrarily by the user in some tenant configurations. Attackers can register an Azure account with a victim's email address, obtain a valid ID token, and log in as the victim.

**Detection:**
```bash
# Check if app accepts email from token for identity binding
# Look for email-based user lookup in API responses or JS source
grep -iE 'email.*login|login.*email|findByEmail|getUserByEmail' /workspace/source/
```

**Test:**
1. Register a new Azure account (personal Microsoft account or attacker-controlled tenant)
2. Set the account's email to the victim's email address
3. Obtain an ID token for the target application from your attacker account
4. Submit the token to the application's login endpoint
5. If the app logs you in as the victim: confirmed nOAuth

**Fix indicator:** Application should bind identity to `oid` + `tid` tuple, never `email` alone.

### Audience (aud) Confusion

**Description:** A token issued for one Azure application (audience A) is accepted by another application (audience B). This allows lateral movement between applications sharing the same Azure tenant.

**Test:**
```bash
# Get token for a lower-privileged app (e.g., your own test app)
# Send it to the target API endpoint
# If accepted: aud confusion confirmed

# Check aud claim in target's expected tokens vs what you have
jwt_tool -t <your_token> -jd | grep '"aud"'

# Attempt with jwt_tool
jwt_tool -t <token> -X a -av "api://target-app-client-id"
```

**Automated check:**
```python
import requests

# Try your token against the target API
headers = {"Authorization": f"Bearer {your_token}"}
r = requests.get("https://target.app/api/sensitive-endpoint", headers=headers)
# 200 with data instead of 401 = aud confusion confirmed
print(r.status_code, r.text[:200])
```

### Multi-Tenant Issuer Validation Bypass

**Description:** Single-tenant apps that accept tokens from any Azure AD tenant (`/common/` endpoint) instead of their specific tenant. Allows any Azure user to authenticate.

**Detection:**
```bash
# Check OIDC discovery — look for /common/ endpoint usage
curl https://target.app/.well-known/openid-configuration 2>/dev/null | python3 -m json.tool | grep issuer

# In MSAL config: if authority is /common/ or /organizations/, multi-tenant is enabled
grep -oE '"authority"\s*:\s*"[^"]*"' /workspace/bundle.js
```

**Test:** Obtain a token from a completely different Azure tenant and send it to the target API. If the `iss` claim contains a different tenant GUID than the app's own tenant and the API accepts it: confirmed.

### Missing or Insufficient Scope Validation

**Description:** The API grants access based only on the presence of a valid token, without verifying that the token contains the required scope (`scp`) or role (`roles`) claim for the requested operation.

**Test:**
```bash
# Obtain a token with minimal scopes (openid profile)
# Attempt to call privileged API endpoints
# Compare behavior with full-scope token vs minimal-scope token

# Check scopes in your current token
jwt_tool -t <token> -jd | grep -E '"scp"|"roles"'
```

### Authorization Code Injection / PKCE Bypass

**Description:** If the application does not enforce PKCE (Proof Key for Code Exchange) and leaks the authorization code (e.g., in Referer header, logs, or redirect), an attacker can exchange it for tokens.

**Test:**
```bash
# Capture the OAuth2 authorization code from the redirect URL
# Check if it appears in Referer headers on subsequent requests
# Check if PKCE code_challenge is required

# Look for code in proxy history
# Caido: filter requests for 'code=' parameter
```

**Browser interception test:**
```python
# Use browser intercept_requests to capture authorization redirects
# Look for ?code= parameter in captured redirect URLs
```

### Redirect URI Manipulation

**Description:** The application's registered redirect URIs accept wildcard or overly broad URIs, allowing an attacker to register a domain that matches and steal authorization codes.

**Test:**
```bash
# From the MSAL config or OIDC discovery, find registered redirect URIs
# Test variations: add subdomain, change path, use different case
# Attempt authorization with modified redirect_uri parameter

# Direct test (open in browser):
https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?
  client_id={app_client_id}
  &response_type=code
  &redirect_uri=https://attacker.com/callback
  &scope=openid+profile
  &response_mode=fragment
```

## Tool Usage

### jwt_tool — Token Analysis and Manipulation
```bash
# Decode and display all claims
jwt_tool -t <token> -jd

# Test none algorithm (rarely works against Microsoft tokens — they use RS256)
jwt_tool -t <token> -X n

# Test algorithm confusion (RS256 → HS256 with public key)
jwt_tool -t <token> -X k -pk /path/to/public_key.pem

# Fuzz claim values
jwt_tool -t <token> -I -hc kid -hv "../../dev/null" -jd
```

### Harvesting Tokens from Network Capture

```python
# After browser_action capture_network, parse Bearer tokens
network_log = [...]  # from capture_network result

bearer_tokens = []
for entry in network_log:
    auth_header = entry.get("request_headers", {}).get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        bearer_tokens.append(token)

# Decode each
import json, base64
for token in bearer_tokens:
    parts = token.split(".")
    if len(parts) >= 2:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        print(json.dumps(claims, indent=2))
```

### MSAL.js Config Extraction from JS Bundles

```bash
# Download and search for MSAL configuration
curl -s https://target.app/static/js/main.js | js-beautify > /workspace/main.js

# Extract the PublicClientApplication config block
grep -A 20 'PublicClientApplication' /workspace/main.js | head -40

# One-liner for all Azure config values
grep -oE '(clientId|tenantId|authority|redirectUri|scopes)["\s:]+["\[]([^"}\]]+)' /workspace/main.js
```

## Token Expiry Handling

Azure AD access tokens expire after **1 hour** by default. Signs of expiry:
- `AADSTS700082`: Refresh token has expired
- `AADSTS70043`: Inactive refresh token
- `AADSTS500011`: Resource principal not found
- HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token"`
- Browser redirect back to `login.microsoftonline.com`

If the pre-configured token is expired:
1. Output clear warning: `AUTH TOKEN EXPIRED (AADSTS error detected) — switching to unauthenticated testing`
2. Continue testing unauthenticated surfaces (public endpoints, error handling, info disclosure)
3. Recommend user re-run with a fresh token obtained from the app's developer tools (Network tab → copy Bearer token from any authenticated API request)

## Reporting Severity Guidance

| Vulnerability | CVSS | Notes |
|---|---|---|
| nOAuth email claim trust | Critical (9.8) | Full account takeover via identity spoofing |
| Audience (aud) confusion | Critical (9.1) | Cross-app token reuse, full auth bypass |
| Multi-tenant issuer bypass | Critical (9.1) | Any Azure user can authenticate |
| Missing scope validation | High (8.1) | Privilege escalation to admin functions |
| Authorization code injection | High (7.5) | Account takeover if PKCE missing |
| Redirect URI open redirect | High (7.5) | Code/token theft via phishing |
| Mutable claim trust (roles/groups) | High (7.5) | Privilege escalation |

Always include in findings:
- Tenant ID (from `tid` claim)
- Application client ID (from `appid`/`azp` claim)
- Affected API endpoint
- Proof-of-concept request showing the bypass
