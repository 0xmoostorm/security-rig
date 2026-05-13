#!/usr/bin/env python3
"""
Static IOC scanner for active supply-chain campaigns.

Current coverage:
- Mini Shai-Hulud / Shai-Hulud: Here We Go Again (May 2026)
  - compromised TanStack npm versions / git dependency injection
  - router_init.js payload hash / filenames
  - PyPI mistralai==2.4.6
  - suspicious .claude/.vscode persistence hooks

No target code is executed. Output is JSON for security-rig findings/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

CAMPAIGN = "mini-shai-hulud-2026-05"
ROUTER_INIT_SHA256 = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
TANSTACK_SETUP_COMMIT = "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
MALICIOUS_TANSTACK_VERSIONS = {"1.169.5", "1.169.8"}
MALICIOUS_PYPI = {"mistralai": {"2.4.6"}}
SUSPICIOUS_NAMES = {"router_init.js", "router_runtime.js", "tanstack_runner.js", "setup.mjs"}
MAX_FILE_BYTES = 25 * 1024 * 1024


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def add(findings: list[dict[str, Any]], severity: str, confidence: str, what: str, where: str, evidence: dict[str, Any], recommendation: str) -> None:
    findings.append({
        "campaign": CAMPAIGN,
        "severity": severity,
        "confidence": confidence,
        "what": what,
        "where": where,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def normalize_version(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    # package-lock sometimes stores =1.2.3 or npm:pkg@1.2.3 forms.
    s = s.lstrip("=v")
    return s


def check_npm_json(root: Path, findings: list[dict[str, Any]]) -> None:
    for path in list(root.rglob("package-lock.json")) + list(root.rglob("package.json")):
        if any(part in {".git"} for part in path.parts):
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue

        candidates: list[tuple[str, str, str]] = []
        if path.name == "package-lock.json":
            packages = data.get("packages")
            if isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if isinstance(meta, dict):
                        name = meta.get("name")
                        if not name and isinstance(pkg_path, str) and "node_modules/" in pkg_path:
                            name = pkg_path.split("node_modules/")[-1]
                        candidates.append((str(name or ""), normalize_version(meta.get("version")), f"packages.{pkg_path}"))
            deps = data.get("dependencies")
            if isinstance(deps, dict):
                for name, meta in deps.items():
                    if isinstance(meta, dict):
                        candidates.append((str(name), normalize_version(meta.get("version")), f"dependencies.{name}"))
        else:
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                deps = data.get(section)
                if isinstance(deps, dict):
                    for name, version in deps.items():
                        candidates.append((str(name), normalize_version(version), f"{section}.{name}"))
                        if name == "@tanstack/setup" and TANSTACK_SETUP_COMMIT in str(version):
                            add(
                                findings,
                                "critical",
                                "high",
                                "TanStack malicious git dependency injection IOC",
                                rel(path, root),
                                {"dependency": name, "specifier": version, "json_path": f"{section}.{name}", "commit": TANSTACK_SETUP_COMMIT},
                                "Do not install. Remove the dependency, inspect install hosts for executed lifecycle hooks, and rotate reachable secrets.",
                            )

        for name, version, json_path in candidates:
            if name.startswith("@tanstack/") and version in MALICIOUS_TANSTACK_VERSIONS:
                add(
                    findings,
                    "critical",
                    "high",
                    "Known compromised TanStack npm package version",
                    rel(path, root),
                    {"package": name, "version": version, "json_path": json_path},
                    "Upgrade/downgrade to a known-good version, delete caches/node_modules, and rotate secrets from any host or CI runner that installed it.",
                )


def check_lockfile_text(root: Path, findings: list[dict[str, Any]]) -> None:
    lock_names = {"pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "npm-shrinkwrap.json"}
    tanstack_re = re.compile(r"@tanstack/[A-Za-z0-9_.\-/]+[^\n]{0,120}(?:1\.169\.5|1\.169\.8)")
    py_re = re.compile(r"(?i)\bmistralai\b[^\n]{0,80}\b2\.4\.6\b")
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in lock_names:
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for m in tanstack_re.finditer(text):
            add(
                findings,
                "critical",
                "medium",
                "Possible known compromised TanStack version in lockfile",
                rel(path, root),
                {"match": m.group(0)[:300]},
                "Confirm the resolved package/version. If installed since 2026-05-11, treat host and CI secrets as exposed.",
            )
        if TANSTACK_SETUP_COMMIT in text:
            add(
                findings,
                "critical",
                "high",
                "TanStack malicious setup commit present in lockfile",
                rel(path, root),
                {"commit": TANSTACK_SETUP_COMMIT},
                "Remove lockfile entry, regenerate from clean dependencies, purge caches, and rotate exposed secrets.",
            )
        for m in py_re.finditer(text):
            add(
                findings,
                "critical",
                "medium",
                "Possible compromised mistralai PyPI version in lockfile",
                rel(path, root),
                {"match": m.group(0)[:300]},
                "Remove mistralai 2.4.6, reinstall a known-good version from clean cache, and rotate secrets from install hosts.",
            )


def check_python_manifests(root: Path, findings: list[dict[str, Any]]) -> None:
    py_files = {"requirements.txt", "requirements-dev.txt", "constraints.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock"}
    exact = re.compile(r"(?im)^\s*mistralai\s*(?:==|=)\s*2\.4\.6\b")
    loose = re.compile(r"(?i)\bmistralai\b[^\n]{0,80}\b2\.4\.6\b")
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in py_files:
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        match = exact.search(text) or loose.search(text)
        if match:
            add(
                findings,
                "critical",
                "high" if exact.search(text) else "medium",
                "Known compromised PyPI package version mistralai==2.4.6",
                rel(path, root),
                {"match": match.group(0)[:300]},
                "Remove mistralai 2.4.6, reinstall from a clean cache, and rotate secrets from any host or CI job that imported/installed it.",
            )


def check_files(root: Path, findings: list[dict[str, Any]]) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part == ".git" for part in path.parts):
            continue
        name = path.name
        interesting = name in SUSPICIOUS_NAMES or ".claude" in path.parts or ".vscode" in path.parts
        if not interesting:
            continue
        evidence: dict[str, Any] = {"filename": name}
        severity = "high" if name in {"router_init.js", "router_runtime.js", "tanstack_runner.js"} else "medium"
        confidence = "medium"
        what = "Suspicious Mini Shai-Hulud-related filename or persistence path"
        try:
            size = path.stat().st_size
            evidence["size"] = size
            if size <= MAX_FILE_BYTES:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                evidence["sha256"] = digest
                if digest == ROUTER_INIT_SHA256:
                    severity = "critical"
                    confidence = "high"
                    what = "Exact router_init.js malware payload hash match"
        except Exception as exc:
            evidence["hash_error"] = str(exc)
        if name in {"settings.json", "tasks.json"}:
            try:
                text = path.read_text(errors="replace")[:20000]
                hits = [s for s in SUSPICIOUS_NAMES if s in text]
                if not hits:
                    continue
                evidence["suspicious_references"] = hits
                what = "Suspicious .vscode hook/task references Mini Shai-Hulud filenames"
                severity = "high"
                confidence = "medium"
            except Exception:
                continue
        add(
            findings,
            severity,
            confidence,
            what,
            rel(path, root),
            evidence,
            "Do not execute this tree. Remove persistence files, purge package caches, and rotate reachable credentials if this was on an install host.",
        )


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    findings: list[dict[str, Any]] = []
    check_npm_json(root, findings)
    check_lockfile_text(root, findings)
    check_python_manifests(root, findings)
    check_files(root, findings)
    out = {
        "scanner": "supply-chain-ioc-scan",
        "campaigns": [CAMPAIGN],
        "root": str(root),
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        },
        "iocs": {
            "router_init_sha256": ROUTER_INIT_SHA256,
            "tanstack_setup_commit": TANSTACK_SETUP_COMMIT,
            "tanstack_versions": sorted(MALICIOUS_TANSTACK_VERSIONS),
            "pypi": {name: sorted(versions) for name, versions in MALICIOUS_PYPI.items()},
        },
        "findings": findings,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
