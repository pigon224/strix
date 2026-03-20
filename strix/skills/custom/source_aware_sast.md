---
name: source-aware-sast
description: Practical source-aware SAST and AST playbook for semgrep, ast-grep, gitleaks, and trivy fs
---

# Source-Aware SAST Playbook

Use this skill for source-heavy analysis where static and structural signals should guide dynamic testing.

## Fast Start

Run tools from repo root and store outputs in a dedicated artifact directory:

```bash
mkdir -p /workspace/.strix-source-aware
```

Before scanning, check shared wiki memory:

```text
1) list_notes(category="wiki")
2) Reuse matching repo wiki note if present
3) create_note(category="wiki") only if missing
```

## Semgrep First Pass

Use Semgrep as the default static triage pass:

```bash
semgrep --config auto --json --output /workspace/.strix-source-aware/semgrep.json .
```

If diff scope is active, restrict to changed files first, then expand only when needed.

## AST-Grep Structural Mapping

Use `sg` for structure-aware code hunting:

```bash
sg scan --json . > /workspace/.strix-source-aware/ast-grep.json
```

Target high-value patterns such as:
- missing auth checks near route handlers
- dynamic command/query construction
- unsafe deserialization or template execution paths
- file and path operations influenced by user input

## Tree-Sitter Assisted Repo Mapping

Use tree-sitter CLI for syntax-aware parsing when grep-level mapping is noisy:

```bash
tree-sitter parse -q <file>
```

Use outputs to improve route/symbol/sink maps for subsequent targeted scans.

## Secret and Supply Chain Coverage

Detect hardcoded credentials:

```bash
gitleaks detect --source . --report-format json --report-path /workspace/.strix-source-aware/gitleaks.json
trufflehog filesystem --json . > /workspace/.strix-source-aware/trufflehog.json
```

Run repository-wide dependency and config checks:

```bash
trivy fs --format json --output /workspace/.strix-source-aware/trivy-fs.json .
```

## Converting Static Signals Into Exploits

1. Rank candidates by impact and exploitability.
2. Trace source-to-sink flow for top candidates.
3. Build dynamic PoCs that reproduce the suspected issue.
4. Report only after dynamic validation succeeds.

## Wiki Update Template

Keep one wiki note per repository and update these sections:

```text
## Architecture
## Entrypoints
## AuthN/AuthZ
## High-Risk Sinks
## Static Findings Summary
## Dynamic Validation Follow-Ups
```

## Anti-Patterns

- Do not treat scanner output as final truth.
- Do not spend full cycles on low-signal pattern matches.
- Do not report source-only findings without validation evidence.
- Do not create multiple wiki notes for the same repository when one already exists.
