from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_env() -> dict[str, str]:
    allowed = {"PATH", "Path", "PATHEXT", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _base_run(name: str, root: Path, executable: str, args: list[str], timeout_seconds: int) -> dict[str, Any]:
    started_at = _now()
    started = time.perf_counter()
    available_path = shutil.which(executable)
    result: dict[str, Any] = {
        "name": name,
        "executable": executable,
        "available": bool(available_path),
        "status": "not_installed" if not available_path else "running",
        "started_at": started_at,
        "ended_at": None,
        "duration_ms": 0,
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "findings": [],
        "error": None,
    }
    if not available_path:
        result["ended_at"] = _now()
        result["duration_ms"] = round((time.perf_counter() - started) * 1000)
        return result
    try:
        completed = subprocess.run(
            [available_path, *args],
            cwd=str(root),
            env=_safe_env(),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
        result["return_code"] = completed.returncode
        result["stdout"] = completed.stdout[-2_000_000:]
        result["stderr"] = completed.stderr[-100_000:]
        result["status"] = "completed" if completed.returncode in (0, 1) else "failed"
        if completed.returncode not in (0, 1):
            result["error"] = f"{name} exited with code {completed.returncode}"
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"{name} exceeded the {timeout_seconds}s timeout"
    except OSError as exc:
        result["status"] = "failed"
        result["error"] = f"Could not execute {name}: {exc.__class__.__name__}"
    finally:
        result["ended_at"] = _now()
        result["duration_ms"] = round((time.perf_counter() - started) * 1000)
    return result


def _severity(value: str | None) -> str:
    normalized = (value or "medium").lower()
    return "Critical" if normalized in {"critical", "error"} else "High" if normalized in {"high"} else "Low" if normalized in {"low", "info", "informational"} else "Medium"


def run_semgrep(root: Path, timeout_seconds: int = 45) -> dict[str, Any]:
    result = _base_run("Semgrep", root, "semgrep", ["scan", "--config", "p/default", "--json", "--quiet", "--no-git-ignore", "."], timeout_seconds)
    if result["status"] not in {"completed"}:
        return result
    try:
        document = json.loads(result["stdout"] or "{}")
        for raw in document.get("results", []):
            extra = raw.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            start = raw.get("start", {}) or {}
            path = str(raw.get("path", "")).replace("\\", "/")
            result["findings"].append(
                {
                    "id": f"semgrep:{raw.get('check_id', 'unknown')}:{path}:{start.get('line', 0)}",
                    "type": "external_static_finding",
                    "title": extra.get("message") or raw.get("check_id", "Semgrep finding"),
                    "severity": _severity(extra.get("severity") or metadata.get("severity")),
                    "confidence": 0.88,
                    "source": "semgrep",
                    "scanner_rule_ids": [raw.get("check_id", "unknown")],
                    "file": path,
                    "line": int(start.get("line", 0) or 0),
                    "snippet": extra.get("lines", ""),
                    "evidence": extra.get("lines", ""),
                    "explanation": extra.get("message", "Semgrep identified a security pattern."),
                    "impact": "Review the scanner evidence and affected data flow before treating this as exploitable.",
                    "remediation": "Follow the Semgrep rule guidance and review the surrounding function before applying a patch.",
                    "related_files": [],
                    "attack_path": [],
                    "patch_available": False,
                    "cwe": (metadata.get("cwe") or [None])[0] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
                }
            )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        result["status"] = "failed"
        result["error"] = f"Semgrep returned invalid JSON: {exc.__class__.__name__}"
    return result


def run_bandit(root: Path, timeout_seconds: int = 45) -> dict[str, Any]:
    result = _base_run("Bandit", root, "bandit", ["-r", ".", "-f", "json", "-q"], timeout_seconds)
    if result["status"] not in {"completed"}:
        return result
    try:
        document = json.loads(result["stdout"] or "{}")
        for raw in document.get("results", []):
            result["findings"].append(
                {
                    "id": f"bandit:{raw.get('test_id', 'unknown')}:{raw.get('filename', '')}:{raw.get('line_number', 0)}",
                    "type": "external_static_finding",
                    "title": raw.get("issue_text", "Bandit finding"),
                    "severity": _severity(raw.get("issue_severity")),
                    "confidence": {"HIGH": 0.94, "MEDIUM": 0.76, "LOW": 0.55}.get(str(raw.get("issue_confidence", "MEDIUM")).upper(), 0.7),
                    "source": "bandit",
                    "scanner_rule_ids": [raw.get("test_id", "unknown")],
                    "file": str(raw.get("filename", "")).replace("\\", "/"),
                    "line": int(raw.get("line_number", 0) or 0),
                    "snippet": raw.get("code", ""),
                    "evidence": raw.get("issue_text", ""),
                    "explanation": raw.get("issue_text", "Bandit identified a Python security pattern."),
                    "impact": "Review the Bandit evidence in the surrounding code and confirm reachability.",
                    "remediation": "Follow the Bandit rule guidance and preserve behavior with the smallest safe change.",
                    "related_files": [],
                    "attack_path": [],
                    "patch_available": False,
                    "cwe": (raw.get("issue_cwe") or {}).get("id") if isinstance(raw.get("issue_cwe"), dict) else None,
                }
            )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        result["status"] = "failed"
        result["error"] = f"Bandit returned invalid JSON: {exc.__class__.__name__}"
    return result

