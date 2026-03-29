<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### Open-source AI agents for automated penetration testing.

<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI Version"></a>

</div>

---

Strix runs teams of AI agents that act like real hackers — they navigate your app, find vulnerabilities, and prove them with working PoCs. No false positives from static analysis, no manual setup per engagement.

<div align="center">
  <a href="https://strix.ai">
    <img src=".github/screenshot.png" alt="Strix Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>

---

## Quick Start

**Prerequisites:** Docker (running) + an LLM API key

```bash
# Install
curl -sSL https://strix.ai/install | bash

# Configure
export STRIX_LLM="anthropic/claude-sonnet-4-6"
export LLM_API_KEY="your-api-key"

# Run
strix --target https://your-app.com
```

> First run pulls the sandbox Docker image automatically. Results are saved to `strix_runs/<run-name>`.

---

## Running from Source (Poetry)

[Poetry](https://python-poetry.org/) is a Python dependency and packaging manager. Instead of installing Strix globally, you can run it directly from this repository using the local virtual environment Poetry manages.

```bash
# Install Poetry (if you don't have it)
pip install poetry

# Install project dependencies into a local .venv
poetry install

# Run Strix
poetry run strix --target http://localhost:3000/
```

Alternatively, activate the virtual environment once and use `strix` directly for the rest of your session:

```bash
# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

strix --target http://localhost:3000/
```

---

## Usage

```bash
# Web application scan
strix --target https://your-app.com

# Authenticated scan — inject a Bearer token (e.g. Microsoft Azure AD)
strix --target https://your-app.com --auth-token "eyJ..."

# Inject custom headers or cookies
strix --target https://your-app.com \
  --auth-header "X-Api-Key: secret" \
  --auth-cookie "session=abc123"

# Restrict scope strictly — block subdomains like api.other.com when target is your-app.com
strix --target https://your-app.com --scope-strict-domains

# Scan a local codebase or GitHub repo
strix --target ./app-directory
strix --target https://github.com/org/repo

# Multi-target (source + deployed)
strix -t https://github.com/org/app -t https://your-app.com

# Custom instructions (scope, focus areas, rules of engagement)
strix --target https://your-app.com --instruction "Focus on IDOR and business logic flaws"
strix --target https://your-app.com --instruction-file ./rules.md

# Non-interactive / headless (for CI)
strix -n --target https://your-app.com
```

### Configuration

```bash
export STRIX_LLM="anthropic/claude-sonnet-4-6"   # or openai/gpt-5.4, vertex_ai/gemini-3-pro-preview
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="http://localhost:11434"       # local model (Ollama, LMStudio)
export PERPLEXITY_API_KEY="your-key"               # enables web search during recon
export STRIX_REASONING_EFFORT="high"               # high (default) or medium (faster)
```

Configuration is saved to `~/.strix/cli-config.json` on first run.

### CI/CD (GitHub Actions)

```yaml
name: strix-penetration-test
on:
  pull_request:
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash
      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: strix -n -t ./ --scan-mode quick
```

---

## What Strix Tests

- **Access control** — IDOR, privilege escalation, auth bypass
- **Injection** — SQL, NoSQL, command, SSTI
- **Server-side** — SSRF, XXE, path traversal, deserialization
- **Client-side** — XSS, prototype pollution, DOM vulnerabilities, SPA framework issues
- **Authentication** — JWT attacks, session management, Azure AD / OAuth flows
- **Business logic** — race conditions, workflow manipulation
- **Infrastructure** — misconfigurations, exposed services, security headers

---

## Automated Scanner (ZAP)

When the `zaproxy/zap-stable` Docker image is available on the host, Strix automatically starts an OWASP ZAP sidecar container and gives agents access to it for broad automated coverage — spider, AJAX spider, active scan, and alert retrieval — before targeted manual testing begins.

```bash
# Pull the image once to enable ZAP
docker pull zaproxy/zap-stable
```

---

## Strix Platform

The hosted version at **[app.strix.ai](https://app.strix.ai)** adds continuous monitoring, one-click autofixes as PRs, GitHub/Slack/Jira integrations, and enterprise controls (SSO, VPC deployment, SLA). [Start free →](https://app.strix.ai)

---

## Documentation

Full docs at **[docs.strix.ai](https://docs.strix.ai)** — LLM providers, skills, CI/CD, advanced configuration.

## Contributing

Contributions welcome — code, docs, and new skills. See [Contributing Guide](https://docs.strix.ai/contributing) or open a [PR](https://github.com/usestrix/strix/pulls) / [issue](https://github.com/usestrix/strix/issues).

**[Join our Discord](https://discord.gg/strix-ai)** for questions and community discussion.

## Acknowledgements

Built on [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), [OWASP ZAP](https://github.com/zaproxy/zaproxy), and [Textual](https://github.com/Textualize/textual).

> [!WARNING]
> Only test applications you own or have explicit written permission to test. You are responsible for using Strix ethically and legally.
