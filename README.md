# security-rig

Local Docker container that takes a repo URL and produces a security investigation report.

Point it at any GitHub repo. It clones (safely), runs supply-chain scanners + SAST + secret detection in parallel, and optionally hands the raw findings to a Claude or Codex agent for synthesis. Output is a single `report.md` plus the raw scanner JSON.

The container is the isolation boundary — a malicious repo can't touch your host, and the cloned working tree is tarred and removed by default so nothing extracted lives on your bind mount.

## What's inside

| Layer | Tools |
|-------|-------|
| Supply chain | Aikido Safe Chain runtime hardening, depenemy, osv-scanner, trivy, grype, campaign IOC scanner |
| SAST | semgrep (auto-config), codeql (opt-in) |
| Secrets | gitleaks |
| Agents | Claude Code, Codex |

## Install / CLI

```bash
git clone https://github.com/0xmoostorm/security-rig.git
cd security-rig
./bin/security-rig build
```

Optional: put the host CLI on your PATH:

```bash
ln -sf "$PWD/bin/security-rig" ~/.local/bin/security-rig
```

Then use:

```bash
security-rig scan https://github.com/owner/repo
security-rig doctor
security-rig help
```

First build is slow (~5 min) — pulls trivy, grype, osv-scanner, gitleaks, all npm globals.

## First-time auth (Claude Code / Codex)

The named volumes `claude-auth` and `codex-auth` persist OAuth across container restarts so you only log in once.

```bash
./bin/security-rig login claude
./bin/security-rig login codex
```

You only need whichever agent you plan to use for synthesis (default is Codex).

## Run — basic investigation

```bash
./bin/security-rig scan https://github.com/owner/repo
```

Output lands in `./work/<repo>-<timestamp>/` on the host:
- `findings/*.json` — raw scanner output
- `source.tar.gz` — the cloned repo, archived (extracted tree is removed by default — see safety section below)

## Run — with agent synthesis

```bash
./bin/security-rig scan https://github.com/owner/repo --synth
```

Default agent is **Codex**. To use Claude instead:

```bash
./bin/security-rig scan https://github.com/owner/repo --synth --agent claude
```

The synthesis pass reads `findings/*.json` and writes `report.md` per the prompt at `prompts/synthesize-report.md`.

## Agent skill

This repo ships an agent-facing `SKILL.md`. Agents can load it as procedural context before operating the rig. It captures the safe scan workflow, output interpretation order, Mini Shai-Hulud coverage, and reporting pitfalls.

## Safety: what's on your host bind-mount

By default `./work/` on your host sees only:
- `findings/*.json` — inert text
- `source.tar.gz` — inert archive
- `report.md` — synthesis output (text)

The cloned working tree is **deleted** after scanning. Pass `--keep-source` to retain it.

**Why:** a malicious repo can include symlinks, install hooks, or VSCode workspace settings that execute on host if you `cd` in or open the folder. The defaults reduce that surface.

Mitigations baked in:
- `git -c core.symlinks=false clone` — symlinks are skipped at clone time
- `--no-recurse-submodules` — no untrusted submodule pulls
- working tree tarred + removed after scan unless `--keep-source`

If you ever do use `--keep-source`, **don't open `./work/<repo>/repo/` in VSCode or your editor** — open `findings/` and the tarball, never the live tree.

## Run — interactive shell

```bash
./bin/security-rig shell
```

Then drive any of the tools directly. `claude` and `codex` are on PATH.

## Output layout

```
work/
└── repo-20260427-143012/
    ├── repo/              # cloned source (removed unless --keep-source)
    ├── findings/
    │   ├── safe-chain.json       # Aikido Safe Chain setup/verification status
    │   ├── supply-chain-ioc-scan.json
    │   ├── depenemy.json
    │   ├── osv-scanner.json
    │   ├── trivy.json
    │   ├── grype.json
    │   ├── gitleaks.json
    │   └── semgrep.json
    └── report.md          # only if --synth
```

## Aikido Safe Chain runtime hardening

The image includes a pinned Aikido Safe Chain binary. Each `investigate` run executes
`safe-chain setup-ci`, prepends `~/.safe-chain/shims` to PATH, verifies npm/pip
wrappers, and writes `findings/safe-chain.json`. This protects package-manager
commands that run inside the rig from known-malicious npm/PyPI packages and from
packages younger than Safe Chain's minimum-age policy.

This is defense-in-depth for runtime package downloads. It does **not** replace the
static scanners or campaign IOC scanner, because Safe Chain only triggers when a
package manager downloads packages.

## Caveats / known gotchas

- **Network is open by default.** Investigate is calling out to npm/PyPI/OSV/etc. If you're scanning something nasty, consider `--network=none` and pre-cache deps.
- **Codex bubblewrap** — bubblewrap can't create user namespaces inside an unprivileged container, so `investigate` passes `--sandbox danger-full-access` to codex during synthesis. The container itself is the isolation boundary.
- **CodeQL is heavy.** ~500MB image growth + slow analysis. Disabled by default; uncomment the block in `Dockerfile` if you want it.
- **No CodeQL queries baked in.** If you enable it, you'll want to also COPY in the codeql query bundles or download at first run.
- **Auto-config Semgrep makes network calls.** If running offline, swap for `--config=p/security-audit` or similar.

## Roadmap

- [x] v1: tools-only validation
- [x] v2: claude/codex synthesis pass
- [ ] v3: orchestrator + scanner-runner + report-writer topology
- [ ] v4: webhook → Slack / Linear when investigation completes

## License

MIT — see [LICENSE](LICENSE).
