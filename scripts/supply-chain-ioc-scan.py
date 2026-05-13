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
TANSTACK_RUNNER_SHA256 = "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
TANSTACK_SETUP_COMMIT = "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
# Source: Aikido Security, "Mini Shai-Hulud Is Back: npm Worm Hits over 160 Packages, including Mistral and Tanstack"
# Retrieved from https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised on 2026-05-13.
AFFECTED_NPM = {
    "@beproduct/nestjs-auth": [
        "0.1.2",
        "0.1.3",
        "0.1.4",
        "0.1.5",
        "0.1.6",
        "0.1.7",
        "0.1.8",
        "0.1.9",
        "0.1.10",
        "0.1.11",
        "0.1.12",
        "0.1.13",
        "0.1.14",
        "0.1.15",
        "0.1.16",
        "0.1.17",
        "0.1.18",
        "0.1.19"
    ],
    "@dirigible-ai/sdk": [
        "0.6.2",
        "0.6.3"
    ],
    "@draftauth/client": [
        "0.2.1",
        "0.2.2"
    ],
    "@draftauth/core": [
        "0.13.1",
        "0.13.2"
    ],
    "@draftlab/auth": [
        "0.24.1",
        "0.24.2"
    ],
    "@draftlab/auth-router": [
        "0.5.1",
        "0.5.2"
    ],
    "@draftlab/db": [
        "0.16.1"
    ],
    "@mesadev/rest": [
        "0.28.3"
    ],
    "@mesadev/saguaro": [
        "0.4.22"
    ],
    "@mesadev/sdk": [
        "0.28.3"
    ],
    "@mistralai/mistralai": [
        "2.2.2",
        "2.2.3",
        "2.2.4"
    ],
    "@mistralai/mistralai-azure": [
        "1.7.1",
        "1.7.2",
        "1.7.3"
    ],
    "@mistralai/mistralai-gcp": [
        "1.7.1",
        "1.7.2",
        "1.7.3"
    ],
    "@ml-toolkit-ts/preprocessing": [
        "1.0.2",
        "1.0.3"
    ],
    "@ml-toolkit-ts/xgboost": [
        "1.0.3",
        "1.0.4"
    ],
    "@squawk/airport-data": [
        "0.7.4",
        "0.7.5",
        "0.7.6",
        "0.7.7"
    ],
    "@squawk/airports": [
        "0.6.2",
        "0.6.3",
        "0.6.4",
        "0.6.5"
    ],
    "@squawk/airspace": [
        "0.8.1",
        "0.8.2",
        "0.8.3",
        "0.8.4"
    ],
    "@squawk/airspace-data": [
        "0.5.3",
        "0.5.4",
        "0.5.5",
        "0.5.6"
    ],
    "@squawk/airway-data": [
        "0.5.4",
        "0.5.5",
        "0.5.6",
        "0.5.7"
    ],
    "@squawk/airways": [
        "0.4.2",
        "0.4.3",
        "0.4.4",
        "0.4.5"
    ],
    "@squawk/fix-data": [
        "0.6.4",
        "0.6.5",
        "0.6.6",
        "0.6.7"
    ],
    "@squawk/fixes": [
        "0.3.2",
        "0.3.3",
        "0.3.4",
        "0.3.5"
    ],
    "@squawk/flight-math": [
        "0.5.4",
        "0.5.5",
        "0.5.6",
        "0.5.7"
    ],
    "@squawk/flightplan": [
        "0.5.2",
        "0.5.3",
        "0.5.4",
        "0.5.5"
    ],
    "@squawk/geo": [
        "0.4.4",
        "0.4.5",
        "0.4.6",
        "0.4.7"
    ],
    "@squawk/icao-registry": [
        "0.5.2",
        "0.5.3",
        "0.5.4",
        "0.5.5"
    ],
    "@squawk/icao-registry-data": [
        "0.8.4",
        "0.8.5",
        "0.8.6",
        "0.8.7"
    ],
    "@squawk/mcp": [
        "0.9.1",
        "0.9.2",
        "0.9.3",
        "0.9.4"
    ],
    "@squawk/navaid-data": [
        "0.6.4",
        "0.6.5",
        "0.6.6",
        "0.6.7"
    ],
    "@squawk/navaids": [
        "0.4.2",
        "0.4.3",
        "0.4.4",
        "0.4.5"
    ],
    "@squawk/notams": [
        "0.3.6",
        "0.3.7",
        "0.3.8",
        "0.3.9"
    ],
    "@squawk/procedure-data": [
        "0.7.3",
        "0.7.4",
        "0.7.5",
        "0.7.6"
    ],
    "@squawk/procedures": [
        "0.5.2",
        "0.5.3",
        "0.5.4",
        "0.5.5"
    ],
    "@squawk/types": [
        "0.8.2",
        "0.8.3",
        "0.8.4"
    ],
    "@squawk/units": [
        "0.4.3",
        "0.4.4",
        "0.4.5",
        "0.4.6"
    ],
    "@squawk/weather": [
        "0.5.6",
        "0.5.7",
        "0.5.8",
        "0.5.9"
    ],
    "@supersurkhet/cli": [
        "0.0.2",
        "0.0.3",
        "0.0.4",
        "0.0.5",
        "0.0.6",
        "0.0.7"
    ],
    "@supersurkhet/sdk": [
        "0.0.2",
        "0.0.3",
        "0.0.4",
        "0.0.5",
        "0.0.6",
        "0.0.7"
    ],
    "@tallyui/components": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/connector-medusa": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/connector-shopify": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/connector-vendure": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/connector-woocommerce": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/core": [
        "0.2.1",
        "0.2.2",
        "0.2.3"
    ],
    "@tallyui/database": [
        "1.0.1",
        "1.0.2",
        "1.0.3"
    ],
    "@tallyui/pos": [
        "0.1.1",
        "0.1.2",
        "0.1.3"
    ],
    "@tallyui/storage-sqlite": [
        "0.2.1",
        "0.2.2",
        "0.2.3"
    ],
    "@tallyui/theme": [
        "0.2.1",
        "0.2.2",
        "0.2.3"
    ],
    "@tanstack/arktype-adapter": [
        "1.166.12",
        "1.166.15"
    ],
    "@tanstack/eslint-plugin-router": [
        "1.161.9"
    ],
    "@tanstack/eslint-plugin-start": [
        "0.0.4",
        "0.0.7"
    ],
    "@tanstack/history": [
        "1.161.9",
        "1.161.12"
    ],
    "@tanstack/nitro-v2-vite-plugin": [
        "1.154.12",
        "1.154.15"
    ],
    "@tanstack/react-router": [
        "1.169.5",
        "1.169.8"
    ],
    "@tanstack/react-router-devtools": [
        "1.166.16",
        "1.166.19"
    ],
    "@tanstack/react-router-ssr-query": [
        "1.166.15",
        "1.166.18"
    ],
    "@tanstack/react-start": [
        "1.167.68",
        "1.167.71"
    ],
    "@tanstack/react-start-client": [
        "1.166.51",
        "1.166.54"
    ],
    "@tanstack/react-start-rsc": [
        "0.0.47",
        "0.0.50"
    ],
    "@tanstack/react-start-server": [
        "1.166.55",
        "1.166.58"
    ],
    "@tanstack/router-cli": [
        "1.166.46",
        "1.166.49"
    ],
    "@tanstack/router-core": [
        "1.169.5",
        "1.169.8"
    ],
    "@tanstack/router-devtools": [
        "1.166.16",
        "1.166.19"
    ],
    "@tanstack/router-devtools-core": [
        "1.167.6",
        "1.167.9"
    ],
    "@tanstack/router-generator": [
        "1.166.45",
        "1.166.48"
    ],
    "@tanstack/router-plugin": [
        "1.167.38",
        "1.167.41"
    ],
    "@tanstack/router-ssr-query-core": [
        "1.168.3",
        "1.168.6"
    ],
    "@tanstack/router-utils": [
        "1.161.11",
        "1.161.14"
    ],
    "@tanstack/router-vite-plugin": [
        "1.166.53",
        "1.166.56"
    ],
    "@tanstack/solid-router": [
        "1.169.5",
        "1.169.8"
    ],
    "@tanstack/solid-router-devtools": [
        "1.166.16",
        "1.166.19"
    ],
    "@tanstack/solid-router-ssr-query": [
        "1.166.15",
        "1.166.18"
    ],
    "@tanstack/solid-start": [
        "1.167.65",
        "1.167.68"
    ],
    "@tanstack/solid-start-client": [
        "1.166.50",
        "1.166.53"
    ],
    "@tanstack/solid-start-server": [
        "1.166.54",
        "1.166.57"
    ],
    "@tanstack/start-client-core": [
        "1.168.5",
        "1.168.8"
    ],
    "@tanstack/start-fn-stubs": [
        "1.161.9",
        "1.161.12"
    ],
    "@tanstack/start-plugin-core": [
        "1.169.23",
        "1.169.26"
    ],
    "@tanstack/start-server-core": [
        "1.167.33",
        "1.167.36"
    ],
    "@tanstack/start-static-server-functions": [
        "1.166.44",
        "1.166.47"
    ],
    "@tanstack/start-storage-context": [
        "1.166.38",
        "1.166.41"
    ],
    "@tanstack/valibot-adapter": [
        "1.166.12",
        "1.166.15"
    ],
    "@tanstack/virtual-file-routes": [
        "1.161.10",
        "1.161.13"
    ],
    "@tanstack/vue-router": [
        "1.169.5",
        "1.169.8"
    ],
    "@tanstack/vue-router-devtools": [
        "1.166.16",
        "1.166.19"
    ],
    "@tanstack/vue-router-ssr-query": [
        "1.166.15",
        "1.166.18"
    ],
    "@tanstack/vue-start": [
        "1.167.61",
        "1.167.64"
    ],
    "@tanstack/vue-start-client": [
        "1.166.46",
        "1.166.49"
    ],
    "@tanstack/vue-start-server": [
        "1.166.50",
        "1.166.53"
    ],
    "@tanstack/zod-adapter": [
        "1.166.12",
        "1.166.15"
    ],
    "@taskflow-corp/cli": [
        "0.1.24",
        "0.1.25",
        "0.1.26",
        "0.1.27",
        "0.1.28",
        "0.1.29"
    ],
    "@tolka/cli": [
        "1.0.2",
        "1.0.3",
        "1.0.4",
        "1.0.5",
        "1.0.6"
    ],
    "@uipath/access-policy-sdk": [
        "0.3.1"
    ],
    "@uipath/access-policy-tool": [
        "0.3.1"
    ],
    "@uipath/admin-tool": [
        "0.1.1"
    ],
    "@uipath/agent-sdk": [
        "1.0.2"
    ],
    "@uipath/agent-tool": [
        "1.0.1"
    ],
    "@uipath/agent.sdk": [
        "0.0.18"
    ],
    "@uipath/aops-policy-tool": [
        "0.3.1"
    ],
    "@uipath/ap-chat": [
        "1.5.7"
    ],
    "@uipath/api-workflow-tool": [
        "1.0.1"
    ],
    "@uipath/apollo-core": [
        "5.9.2"
    ],
    "@uipath/apollo-react": [
        "4.24.5"
    ],
    "@uipath/apollo-wind": [
        "2.16.2"
    ],
    "@uipath/auth": [
        "1.0.1"
    ],
    "@uipath/case-tool": [
        "1.0.1"
    ],
    "@uipath/cli": [
        "1.0.1"
    ],
    "@uipath/codedagent-tool": [
        "1.0.1"
    ],
    "@uipath/codedagents-tool": [
        "0.1.12"
    ],
    "@uipath/codedapp-tool": [
        "1.0.1"
    ],
    "@uipath/common": [
        "1.0.1"
    ],
    "@uipath/context-grounding-tool": [
        "0.1.1"
    ],
    "@uipath/data-fabric-tool": [
        "1.0.2"
    ],
    "@uipath/docsai-tool": [
        "1.0.1"
    ],
    "@uipath/filesystem": [
        "1.0.1"
    ],
    "@uipath/flow-tool": [
        "1.0.2"
    ],
    "@uipath/functions-tool": [
        "1.0.1"
    ],
    "@uipath/gov-tool": [
        "0.3.1"
    ],
    "@uipath/identity-tool": [
        "0.1.1"
    ],
    "@uipath/insights-sdk": [
        "1.0.1"
    ],
    "@uipath/insights-tool": [
        "1.0.1"
    ],
    "@uipath/integrationservice-sdk": [
        "1.0.2"
    ],
    "@uipath/integrationservice-tool": [
        "1.0.2"
    ],
    "@uipath/llmgw-tool": [
        "1.0.1"
    ],
    "@uipath/maestro-sdk": [
        "1.0.1"
    ],
    "@uipath/maestro-tool": [
        "1.0.1"
    ],
    "@uipath/orchestrator-tool": [
        "1.0.1"
    ],
    "@uipath/packager-tool-apiworkflow": [
        "0.0.19"
    ],
    "@uipath/packager-tool-bpmn": [
        "0.0.9"
    ],
    "@uipath/packager-tool-case": [
        "0.0.9"
    ],
    "@uipath/packager-tool-connector": [
        "0.0.19"
    ],
    "@uipath/packager-tool-flow": [
        "0.0.19"
    ],
    "@uipath/packager-tool-functions": [
        "0.1.1"
    ],
    "@uipath/packager-tool-webapp": [
        "1.0.6"
    ],
    "@uipath/packager-tool-workflowcompiler": [
        "0.0.16"
    ],
    "@uipath/packager-tool-workflowcompiler-browser": [
        "0.0.34"
    ],
    "@uipath/platform-tool": [
        "1.0.1"
    ],
    "@uipath/project-packager": [
        "1.1.16"
    ],
    "@uipath/resource-tool": [
        "1.0.1"
    ],
    "@uipath/resourcecatalog-tool": [
        "0.1.1"
    ],
    "@uipath/resources-tool": [
        "0.1.11"
    ],
    "@uipath/robot": [
        "1.3.4"
    ],
    "@uipath/rpa-legacy-tool": [
        "1.0.1"
    ],
    "@uipath/rpa-tool": [
        "0.9.5"
    ],
    "@uipath/solution-packager": [
        "0.0.35"
    ],
    "@uipath/solution-tool": [
        "1.0.1"
    ],
    "@uipath/solutionpackager-sdk": [
        "1.0.11"
    ],
    "@uipath/solutionpackager-tool-core": [
        "0.0.34"
    ],
    "@uipath/tasks-tool": [
        "1.0.1"
    ],
    "@uipath/telemetry": [
        "0.0.7"
    ],
    "@uipath/test-manager-tool": [
        "1.0.2"
    ],
    "@uipath/tool-workflowcompiler": [
        "0.0.12"
    ],
    "@uipath/traces-tool": [
        "1.0.1"
    ],
    "@uipath/ui-widgets-multi-file-upload": [
        "1.0.1"
    ],
    "@uipath/uipath-python-bridge": [
        "1.0.1"
    ],
    "@uipath/vertical-solutions-tool": [
        "1.0.1"
    ],
    "@uipath/vss": [
        "0.1.6"
    ],
    "@uipath/widget.sdk": [
        "1.2.3"
    ],
    "agentwork-cli": [
        "0.1.4",
        "0.1.5"
    ],
    "cmux-agent-mcp": [
        "0.1.3",
        "0.1.4",
        "0.1.5",
        "0.1.6",
        "0.1.7",
        "0.1.8"
    ],
    "cross-stitch": [
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6"
    ],
    "git-branch-selector": [
        "1.3.3",
        "1.3.4",
        "1.3.5",
        "1.3.6",
        "1.3.7"
    ],
    "git-git-git": [
        "1.0.8",
        "1.0.9",
        "1.0.10",
        "1.0.11",
        "1.0.12"
    ],
    "ml-toolkit-ts": [
        "1.0.4",
        "1.0.5"
    ],
    "nextmove-mcp": [
        "0.1.3",
        "0.1.4",
        "0.1.5",
        "0.1.6",
        "0.1.7"
    ],
    "safe-action": [
        "0.8.3",
        "0.8.4"
    ],
    "ts-dna": [
        "3.0.1",
        "3.0.2",
        "3.0.3",
        "3.0.4"
    ],
    "wot-api": [
        "0.8.1",
        "0.8.2",
        "0.8.3",
        "0.8.4"
    ]
}

AFFECTED_NPM_SETS = {name: set(versions) for name, versions in AFFECTED_NPM.items()}
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
            if name in AFFECTED_NPM_SETS and version in AFFECTED_NPM_SETS[name]:
                add(
                    findings,
                    "critical",
                    "high",
                    "Known compromised npm package version in Mini Shai-Hulud campaign",
                    rel(path, root),
                    {"package": name, "version": version, "json_path": json_path, "source": "Aikido 2026-05-12 affected package list"},
                    "Remove the compromised version, purge package caches/node_modules, and rotate secrets from any host or CI runner that installed it.",
                )


def check_lockfile_text(root: Path, findings: list[dict[str, Any]]) -> None:
    lock_names = {"pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "npm-shrinkwrap.json"}
    py_re = re.compile(r"(?i)\bmistralai\b[^\n]{0,80}\b2\.4\.6\b")
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in lock_names:
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for pkg, versions in AFFECTED_NPM_SETS.items():
            if pkg not in text:
                continue
            for version in versions:
                pattern = re.compile(re.escape(pkg) + r"[^\n]{0,160}" + re.escape(version))
                for m in pattern.finditer(text):
                    add(
                        findings,
                        "critical",
                        "medium",
                        "Possible compromised Mini Shai-Hulud npm package in lockfile",
                        rel(path, root),
                        {"package": pkg, "version": version, "match": m.group(0)[:300]},
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
                elif digest == TANSTACK_RUNNER_SHA256:
                    severity = "critical"
                    confidence = "high"
                    what = "Exact tanstack_runner.js malware payload hash match"
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
            "tanstack_runner_sha256": TANSTACK_RUNNER_SHA256,
            "affected_npm_packages": len(AFFECTED_NPM),
            "affected_npm_package_versions": sum(len(v) for v in AFFECTED_NPM.values()),
            "pypi": {name: sorted(versions) for name, versions in MALICIOUS_PYPI.items()},
        },
        "findings": findings,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
