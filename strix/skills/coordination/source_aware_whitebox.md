---
name: source-aware-whitebox
description: Coordination playbook for source-aware white-box testing with static triage and dynamic validation
---

# Source-Aware White-Box Coordination

Use this coordination playbook when repository source code is available.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic validation. Source-aware tooling is recommended by default, but not mandatory when context suggests a better path.

## Recommended Workflow

1. Build a quick source map before deep exploitation.
2. Run first-pass static triage to rank high-risk paths.
3. Use triage outputs to prioritize dynamic PoC validation.
4. Keep findings evidence-driven: no report without validation.
5. Keep shared wiki memory current so all agents can reuse context.

## Source-Aware Triage Stack

- `semgrep`: fast security-first triage and custom pattern scans
- `ast-grep` (`sg`): structural pattern hunting and targeted repo mapping
- `tree-sitter`: syntax-aware parsing support for symbol and route extraction
- `gitleaks` + `trufflehog`: complementary secret detection (working tree and history coverage)
- `trivy fs`: dependency, misconfiguration, license, and secret checks

## Agent Delegation Guidance

- Keep child agents specialized by vulnerability/component as usual.
- For source-heavy subtasks, prefer creating child agents with `source_aware_sast` skill.
- Use source findings to shape payloads and endpoint selection for dynamic testing.

## Wiki Note Requirement (Source Map)

When source is present, maintain one wiki note per repository and keep it current.

Operational rules:
- At task start, call `list_notes` with `category=wiki` and reuse existing repo wiki if present.
- If no repo wiki exists, create one with `create_note` and `category=wiki`.
- Update the same wiki via `update_note`; avoid creating duplicate wiki notes for the same repo.
- Child agents should read wiki notes first, then extend with new evidence from their scope.

Recommended sections:
- Architecture overview
- Entrypoints and routing
- AuthN/AuthZ model
- High-risk sinks and trust boundaries
- Static scanner summary
- Dynamic validation follow-ups

## Validation Guardrails

- Static findings are hypotheses until validated.
- Dynamic exploitation evidence is still required before vulnerability reporting.
- Keep scanner output concise, deduplicated, and mapped to concrete code locations.
