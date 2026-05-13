---
name: security-rig
description: Use when an agent needs to security-scan a GitHub repository or local codebase with security-rig, especially during active supply-chain campaigns. Provides safe no-install/no-execute triage, scanner invocation, output interpretation, and reporting workflow.
version: 1.0.0
author: 0xMoostorm + Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [security, supply-chain, github, docker, sast, secrets, vulnerability-scanning]
    related_skills: [security-scan, github-repo-management, requesting-code-review]
---

# security-rig

## Overview

`security-rig` is a local Dockerized security investigation rig. Point it at a GitHub repository and it clones the target inside a container, runs supply-chain scanners, SAST, secret detection, and campaign-specific IOC checks, then writes raw JSON findings under `work/<repo>-<timestamp>/findings/`.

The default workflow is designed for hostile repositories and active supply-chain incidents: clone with symlinks disabled, do not recurse submodules, do not install target dependencies, archive the cloned source, and remove the extracted working tree after scanning.

## When to Use

Use this skill when:

- A user asks to scan a GitHub repository for security issues.
- A user asks whether a repo is affected by an active npm/PyPI supply-chain campaign.
- You need static triage for Mini Shai-Hulud / Shai-Hulud indicators.
- You need scanner output from depenemy, OSV, Trivy, Grype, Gitleaks, Semgrep, and the campaign IOC scanner.
- You need a safe first pass before opening a suspicious repository in an editor.

Do not use this as the only step when:

- The request is for a deep manual audit. Treat `security-rig` output as triage and then inspect code manually.
- The repo must be built or tested. That may execute attacker-controlled scripts; require explicit user approval and isolate further.
- The target is private and credentials are not configured for Docker/git.

## Quick Start

From the cloned `security-rig` repo:

```bash
./bin/security-rig build
./bin/security-rig scan https://github.com/owner/repo
```

With agent synthesis:

```bash
./bin/security-rig scan https://github.com/owner/repo --synth
./bin/security-rig scan https://github.com/owner/repo --synth --agent claude
```

Authenticate synthesis agents once, if needed:

```bash
./bin/security-rig login codex
./bin/security-rig login claude
```

Interactive shell:

```bash
./bin/security-rig shell
```

Health check:

```bash
./bin/security-rig doctor
```

## Agent Workflow

1. Start from the rig directory.

   ```bash
   cd /path/to/security-rig
   ./bin/security-rig doctor
   ```

2. Build if the image is missing or Dockerfile changed.

   ```bash
   ./bin/security-rig build
   ```

3. Run the scan.

   ```bash
   ./bin/security-rig scan https://github.com/owner/repo
   ```

4. Find the newest output directory.

   ```bash
   latest=$(ls -td work/*/ | head -1)
   echo "$latest"
   find "$latest/findings" -maxdepth 1 -type f -print | sort
   ```

5. Read the key findings.

   Prioritize:

   - `findings/supply-chain-ioc-scan.json`
   - `findings/gitleaks.json`
   - `findings/osv-scanner.json`
   - `findings/trivy.json`
   - `findings/grype.json`
   - `findings/semgrep.json`
   - `findings/depenemy.json`
   - `findings/safe-chain.json`

6. Summarize in this order:

   - campaign IOC hits or clean result
   - secrets found or clean result
   - critical/high vulnerabilities
   - SAST findings with likely exploitability
   - scanner failures or blind spots
   - recommended next actions

7. Never claim a clean bill of health. Say “no findings from these scanners” and list coverage limits.

## CLI Reference

```bash
security-rig scan <repo-url> [--synth] [--codeql] [--keep-source] [--agent codex|claude]
security-rig shell
security-rig build [--no-cache]
security-rig login codex|claude
security-rig clean
security-rig doctor
security-rig help
```

`scan` passes its arguments directly to the container entrypoint (`investigate`).

Important scan flags:

- `--synth` — ask Codex/Claude inside the container to synthesize raw findings into `report.md`.
- `--agent codex|claude` — select the synthesis agent. Default is Codex.
- `--codeql` — run CodeQL if the image was built with CodeQL enabled.
- `--keep-source` — keep the extracted cloned repo. Avoid unless you need manual inspection and understand the host-editor risk.

## Output Layout

Each scan writes a timestamped directory under `work/`:

```text
work/<repo>-YYYYMMDD-HHMMSS/
├── findings/
│   ├── safe-chain.json
│   ├── supply-chain-ioc-scan.json
│   ├── depenemy.json
│   ├── osv-scanner.json
│   ├── trivy.json
│   ├── grype.json
│   ├── gitleaks.json
│   └── semgrep.json
├── source.tar.gz
└── report.md              # only when --synth is used
```

By default, `repo/` is deleted after being archived into `source.tar.gz`.

## Supply-Chain Campaign Coverage

The built-in campaign IOC scanner is static and executes no target code.

Current Mini Shai-Hulud coverage includes:

- known affected npm package/version indicators
- affected PyPI `mistralai==2.4.6`
- `router_init.js` payload indicators
- known payload hashes such as `router_init.js` and `tanstack_runner.js`
- suspicious `.claude/` and `.vscode/` persistence hooks
- lockfile and manifest evidence where present

Treat IOC coverage as time-sensitive. During an active campaign, update `scripts/supply-chain-ioc-scan.py` when new package/version/hash indicators appear.

## Safety Rules

- Do not run `npm install`, `pip install`, package scripts, test suites, or build commands in the target repo unless the user explicitly approves.
- Prefer the default `scan` mode. It clones inside Docker and removes the extracted source afterward.
- Do not open a retained suspicious repo in VS Code or other host editors. Editor config can be part of the attack surface.
- Avoid `--keep-source` unless manual inspection requires it.
- If a scan finds secrets, do not print secret values. Report file paths, rule IDs, and rotation guidance.
- If scanner JSON is malformed because a tool crashed, report the scanner failure as a blind spot.

## Common Pitfalls

1. Image missing or stale.

   Fix:

   ```bash
   ./bin/security-rig build
   ```

2. Docker daemon unavailable.

   Fix Docker first; `security-rig doctor` should pass before scanning.

3. Private repo clone fails.

   The container needs access to credentials. Prefer a read-only deploy token or clone a safe local mirror only after considering secret exposure.

4. Semgrep `--config=auto` makes network calls.

   This is expected. For offline mode, update the rig to use a local Semgrep ruleset.

5. `--synth` fails because Codex/Claude is not logged in.

   Run:

   ```bash
   ./bin/security-rig login codex
   # or
   ./bin/security-rig login claude
   ```

6. No findings does not mean safe.

   It means these scanners and IOCs did not flag the repository at this point in time.

## Verification Checklist

- [ ] `./bin/security-rig doctor` passes.
- [ ] Scan completed and printed an output directory.
- [ ] `findings/` contains JSON outputs for the expected scanners.
- [ ] `supply-chain-ioc-scan.json` was checked first during active campaigns.
- [ ] Secret values were not exposed in the user-facing summary.
- [ ] Scanner errors/blind spots were explicitly mentioned.
- [ ] Recommendations separate “rotate immediately” actions from “investigate further” actions.
