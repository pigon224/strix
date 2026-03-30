---
name: web-application
description: Web application reconnaissance covering technology fingerprinting, JS bundle analysis, SPA endpoint extraction, API discovery, and attack surface mapping
---

# Web Application Reconnaissance

## Objectives

Before any vulnerability testing, build a complete attack surface map:
- Full endpoint inventory with methods and parameters
- Authentication mechanism identification
- Technology stack and framework versions
- Third-party integrations and dependencies
- High-value targets for focused testing

**Load this skill at the start of every web application assessment.**

## Phase 1: Technology Fingerprinting

### HTTP Headers and Response Analysis

```bash
# Fast tech detection with httpx
httpx -u https://target.app -tech-detect -title -status-code -content-type -web-server -location -o /workspace/httpx_tech.txt

# Single URL detail
httpx -u https://target.app -tech-detect -json | python3 -m json.tool
```

Key response headers to record:
- `Server` — web server (nginx, IIS, Apache) and version
- `X-Powered-By` — runtime (PHP/7.4, ASP.NET, Express)
- `X-Generator` — CMS (WordPress, Drupal, Joomla)
- `X-Frame-Options`, `Content-Security-Policy` — security controls
- `Set-Cookie` names: `PHPSESSID` → PHP, `JSESSIONID` → Java, `ASP.NET_SessionId` → .NET, `__Host-` prefix → secure cookie practices

### WAF and CDN Detection

```bash
wafw00f https://target.app
```

WAF presence affects testing approach: use encoding, case variation, and chunked payloads to bypass.

### robots.txt and Sitemap

```bash
curl -s https://target.app/robots.txt
curl -s https://target.app/sitemap.xml | grep '<loc>' | sed 's/.*<loc>\(.*\)<\/loc>/\1/'
curl -s https://target.app/security.txt
```

## Phase 2: JavaScript Bundle Analysis (Critical for SPAs)

This is the most important recon step for modern web apps. JS bundles expose the entire client-side attack surface.

### Locate All JS Bundles

```bash
# From page source, extract all script tags
curl -s https://target.app | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'

# Common SPA bundle paths
for path in /static/js/main.js /assets/index.js /dist/bundle.js /app.js /js/app.js; do
    httpx -u https://target.app$path -mc 200 -silent && echo "FOUND: $path"
done
```

### Download and Beautify

```bash
curl -s https://target.app/static/js/main.js -o /workspace/main.js
js-beautify /workspace/main.js > /workspace/main_pretty.js
wc -l /workspace/main_pretty.js
```

### Extract API Endpoints

```bash
# REST API paths (most reliable patterns)
grep -oE '"/api/[a-zA-Z0-9/_:?{}-]{2,}"' /workspace/main_pretty.js | sort -u | tr -d '"'
grep -oE '"/v[0-9]+/[a-zA-Z0-9/_:?{}-]{2,}"' /workspace/main_pretty.js | sort -u | tr -d '"'

# Template literals with API calls
grep -oE '`/[a-zA-Z0-9/_${}-]+`' /workspace/main_pretty.js | sort -u

# Fetch/axios/XHR patterns
grep -oE "(fetch|axios\.(get|post|put|delete|patch))\(['\"][^'\"]+['\"]" /workspace/main_pretty.js | \
    grep -oE "['\"][/][^'\"]*['\"]" | tr -d "'\""  | sort -u
```

### Extract Route Definitions

```bash
# React Router v6 (path: "/route")
grep -oE 'path:\s*"[^"]*"' /workspace/main_pretty.js | grep -oE '"[^"]*"' | tr -d '"' | sort -u

# React Router v5 (<Route path="...")
grep -oE 'path=["{][^}"]*["}]' /workspace/main_pretty.js | grep -oE '"[^"]*"' | tr -d '"' | sort -u

# Vue Router
grep -oE "path:\s*'[^']*'" /workspace/main_pretty.js | grep -oE "'[^']*'" | tr -d "'" | sort -u

# Angular router
grep -oE '"path"\s*:\s*"[^"]*"' /workspace/main_pretty.js | grep -oE '"path"\s*:\s*"[^"]*"' | \
    sed 's/"path"\s*:\s*"//;s/"//' | sort -u
```

### Extract Secrets and Config

```bash
# API keys, tokens, client IDs, secrets
trufflehog filesystem /workspace/main_pretty.js --json 2>/dev/null | python3 -m json.tool

# OAuth config
grep -iE 'clientId|tenantId|authority|apiKey|secretKey|token|password' /workspace/main_pretty.js | \
    grep -v '//.*clientId' | head -30

# Hardcoded URLs and internal hostnames
grep -oE 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[/a-zA-Z0-9._?&=-]*' /workspace/main_pretty.js | \
    sort -u | grep -v 'cdn\|fonts\|analytics\|amazonaws.com/static'
```

### Check for Source Maps (Full Source Exposure)

```bash
# If .map files are accessible, they contain original unminified source
curl -s https://target.app/static/js/main.js.map -o /workspace/main.js.map
# A 200 response with JSON = full source code exposed (Critical finding)
python3 -c "
import json, os
with open('/workspace/main.js.map') as f:
    m = json.load(f)
print('Sources:', len(m.get('sources',[])))
print('First 5:', m.get('sources',[])[:5])
"
```

## Phase 3: Crawler-Based Discovery

### katana — SPA-Aware JS Crawling

```bash
# Full JS-rendered crawl (best for React/Angular/Vue)
katana -u https://target.app -js-crawl -d 5 -c 10 \
    -H "Authorization: Bearer TOKEN" \
    -o /workspace/katana_out.txt 2>/dev/null

# With proxy for interception
katana -u https://target.app -js-crawl -proxy http://localhost:48080 -d 5 \
    -o /workspace/katana_out.txt
```

### gospider — Traditional Link Crawling

```bash
gospider -s https://target.app -d 3 \
    -o /workspace/gospider_out/ \
    --js --sitemap --robots \
    -H "Authorization: Bearer TOKEN"
```

### Aggregate All Discovered URLs

```python
import os, re
from pathlib import Path

discovered = set()

# From katana output
if os.path.exists('/workspace/katana_out.txt'):
    with open('/workspace/katana_out.txt') as f:
        discovered.update(line.strip() for line in f if line.strip())

# From JS bundle extraction
if os.path.exists('/workspace/main_pretty.js'):
    with open('/workspace/main_pretty.js') as f:
        content = f.read()
    paths = re.findall(r'"/(?:api|v\d+)/[a-zA-Z0-9/_:?{}-]{2,}"', content)
    discovered.update(p.strip('"') for p in paths)

# Deduplicate and sort
endpoints = sorted(discovered)
with open('/workspace/all_endpoints.txt', 'w') as f:
    f.write('\n'.join(endpoints))
print(f"Total unique endpoints: {len(endpoints)}")
for ep in endpoints[:30]:
    print(ep)
```

## Phase 4: API Specification Discovery

### OpenAPI / Swagger Endpoint Hunting

```bash
swagger_paths=(
    "/swagger.json" "/swagger/v1/swagger.json" "/api/swagger.json"
    "/openapi.json" "/api/openapi.json" "/openapi.yaml"
    "/api-docs" "/v2/api-docs" "/v3/api-docs"
    "/api/v1/swagger.json" "/api/v2/swagger.json" "/api/v3/swagger.json"
    "/swagger-ui.html" "/swagger-ui/" "/api/docs" "/redoc"
    "/api/schema/" "/schema/" "/.well-known/openapi"
)

for path in "${swagger_paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.app$path")
    [ "$code" = "200" ] && echo "FOUND ($code): $path"
done
```

If a spec is found, parse all endpoints:

```python
import json, requests

spec = requests.get("https://target.app/swagger.json").json()
base = spec.get("basePath", "")

for path, methods in spec.get("paths", {}).items():
    for method in methods:
        if method.upper() in ["GET","POST","PUT","PATCH","DELETE","OPTIONS"]:
            print(f"{method.upper()} {base}{path}")
```

### GraphQL Detection

```bash
# Common GraphQL endpoint paths
for path in /graphql /api/graphql /gql /query /api/query; do
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}' \
        "https://target.app$path" | grep -q '__typename' && echo "GraphQL found at $path"
done
```

## Phase 5: Parameter Discovery

### arjun — Hidden Parameter Fuzzing

```bash
# GET parameter discovery on key endpoints
arjun -u https://target.app/api/users -m GET -o /workspace/arjun_users.json

# POST parameter discovery
arjun -u https://target.app/api/login -m POST -o /workspace/arjun_login.json

# Batch all discovered endpoints
cat /workspace/all_endpoints.txt | while read ep; do
    arjun -u "https://target.app$ep" -m GET -q 2>/dev/null
done
```

### Directory Fuzzing for Hidden Endpoints

```bash
# Directories
ffuf -u https://target.app/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -H "Authorization: Bearer TOKEN" \
    -mc 200,201,301,302,401,403 \
    -o /workspace/ffuf_dirs.json -of json -t 50

# API versioning (v1, v2, v3...)
ffuf -u https://target.app/api/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,201,401,403 \
    -o /workspace/ffuf_api.json -of json
```

## Phase 6: Network Traffic Analysis via Browser

```
1. browser_action launch url=https://target.app
2. Navigate through ALL major application flows:
   - Login / logout
   - Main dashboard / home
   - User profile / settings
   - Core business features (each major section)
   - Search / filter functionality
   - File upload (if present)
   - Admin panel (if accessible)
3. browser_action capture_network max_entries=200
4. Parse captured traffic for unique endpoints, auth headers, and request patterns
```

```python
# Parse network capture for attack surface
network_log = [...]  # from capture_network

seen = {}
for entry in network_log:
    url = entry.get("url", "")
    method = entry.get("method", "GET")
    status = entry.get("status")

    # Skip static assets
    if any(ext in url for ext in ['.js', '.css', '.png', '.jpg', '.ico', '.woff']):
        continue

    key = f"{method} {url.split('?')[0]}"
    if key not in seen:
        seen[key] = {
            "method": method,
            "url": url,
            "status": status,
            "has_auth": "authorization" in {k.lower() for k in entry.get("request_headers", {})},
            "has_body": bool(entry.get("request_body")),
        }

# Print attack surface
for key, info in sorted(seen.items()):
    auth_marker = " [AUTH]" if info["has_auth"] else ""
    print(f"{info['method']} {info['url']}{auth_marker} → {info['status']}")
```

## Attack Surface Map Deliverable

At the end of recon, produce a structured map:

```
TARGET: https://target.app
TECH STACK: React SPA, Node.js/Express API, PostgreSQL
AUTH: Azure AD (MSAL.js detected, tenant: xxx, client: yyy)
WAF: Cloudflare

ENDPOINTS (xx discovered):
  PUBLIC:
    GET  /api/health
    GET  /api/products
  AUTHENTICATED:
    GET  /api/users/me           [IDOR candidate]
    GET  /api/users/{id}         [IDOR candidate]
    POST /api/orders             [business logic candidate]
    POST /api/upload             [file upload candidate]
  ADMIN (403 unauthenticated):
    GET  /api/admin/users        [auth bypass candidate]
    POST /api/admin/roles        [privilege escalation candidate]

HIGH-VALUE TARGETS:
  1. /api/users/{id} — enumerate user IDs for IDOR
  2. /api/upload — test all file upload bypass techniques
  3. /api/admin/* — test 403 bypass methods
  4. GraphQL at /graphql — run introspection + alias batching

SECRETS FOUND IN JS:
  - API key: [REDACTED - report as info disclosure]
  - Internal service URL: https://internal.company.com
```

Feed this map to the root agent for targeted agent spawning.
