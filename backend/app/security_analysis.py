from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), "Critical"),
    ("Private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Critical"),
    ("Database URL", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s\"']+", re.I), "High"),
    ("JWT or access token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "High"),
    ("Credential-like assignment", re.compile(r"((?:api[_-]?key|access[_-]?key|secret|password|token|client_secret)\s*[:=]\s*[\"'])([^\"']{8,})([\"'])", re.I), "High"),
]
REDACTION_PATTERNS = [pattern for _, pattern, _ in SECRET_PATTERNS]


def redact_secret_text(text: str) -> str:
    redacted = text
    for pattern in REDACTION_PATTERNS:
        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            if match.lastindex == 3:
                secret = match.group(2)
                masked = f"{secret[:4]}{'*' * max(8, len(secret) - 8)}{secret[-4:]}"
                return f"{match.group(1)}{masked}{match.group(3)}"
            if len(value) <= 8:
                return "*" * len(value)
            return f"{value[:4]}{'*' * max(8, len(value) - 8)}{value[-4:]}"
        redacted = pattern.sub(replace, redacted)
    return redacted


def _read(path: Path, limit: int = 1_500_000) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def _snippet(text: str, line: int, radius: int = 2) -> str:
    lines = text.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{index + 1:>4}  {redact_secret_text(lines[index])}" for index in range(start, end))


def _id(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def scan_secrets(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    excluded = {".git", "node_modules", ".venv", "venv", "__pycache__", ".clankershield"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        text = _read(path)
        if text is None:
            continue
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern, severity in SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                finding_id = _id(f"secret|{relative}|{line_number}|{label}")
                findings.append(
                    {
                        "id": finding_id,
                        "type": "secret_exposure",
                        "title": f"Potential {label.lower()}",
                        "severity": severity,
                        "confidence": 0.96 if severity == "Critical" else 0.9,
                        "source": "secret-scanner",
                        "file": relative,
                        "line": line_number,
                        "snippet": _snippet(text, line_number),
                        "evidence": redact_secret_text(line.strip()),
                        "explanation": "A credential-shaped value was detected in repository content. The value is redacted in ClankerShield output and should not be sent to an AI provider.",
                        "impact": "Anyone with access to this repository or its build artifacts may be able to impersonate the application or access a third-party system.",
                        "remediation": "Rotate the credential, remove it from source control, and load it from a managed secret store or environment variable.",
                        "related_files": [],
                        "attack_path": ["Source repository", "Credential in source", "Clone or build artifact", "Third-party service"],
                        "patch_available": False,
                        "secret_redacted": True,
                    }
                )
                break
    return findings


def _canonical_type(finding_type: str, title: str = "") -> str:
    if finding_type == "hardcoded_secret":
        return "secret_exposure"
    if finding_type == "external_static_finding":
        lowered = title.lower()
        if "sql" in lowered:
            return "sql_injection"
        if "command" in lowered or "shell" in lowered or "subprocess" in lowered:
            return "command_injection"
        if "path traversal" in lowered or "directory traversal" in lowered:
            return "path_traversal"
    return finding_type


def _risk(finding: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    severity = finding.get("severity", "Low")
    kind = _canonical_type(finding.get("type", "unknown"))
    exploitability = "High" if kind in {"sql_injection", "command_injection", "xss", "path_traversal"} else "Medium"
    external = bool(inventory.get("api_routes")) and kind not in {"vulnerable_dependency", "secret_exposure"}
    data_sensitivity = "High" if kind in {"sql_injection", "secret_exposure", "insecure_authentication"} else "Medium"
    reachability = "Reachable" if finding.get("attack_path", [""])[0] in {"HTTP request", "Request parameter", "Client credential"} else "Context-dependent"
    evidence_strength = "Strong" if finding.get("confidence", 0) >= 0.9 else "Moderate"
    score = SEVERITY_WEIGHT.get(severity, 1) * 12
    score += {"High": 24, "Medium": 13, "Low": 6}[exploitability]
    score += 14 if external else 4
    score += 12 if data_sensitivity == "High" else 6
    score += 10 if reachability == "Reachable" else 3
    score += round(float(finding.get("confidence", 0.5)) * 10)
    score = min(100, score)
    band = "Critical" if score >= 82 else "High" if score >= 62 else "Medium" if score >= 38 else "Low"
    return {
        "score": score,
        "band": band,
        "exploitability": exploitability,
        "external_exposure": "External" if external else "Internal or unknown",
        "data_sensitivity": data_sensitivity,
        "reachability": reachability,
        "evidence_strength": evidence_strength,
        "authentication_required": "Unknown from local evidence",
        "privileges_required": "Service account or user context",
    }


def _path_nodes(finding: dict[str, Any]) -> list[dict[str, Any]]:
    labels = finding.get("attack_path") or []
    nodes = []
    for index, label in enumerate(labels):
        location = {"file": finding.get("file"), "line": finding.get("line")} if index in {1, len(labels) - 2} else None
        nodes.append({"id": f"{finding.get('id')}-{index}", "label": label, "kind": "sink" if index == len(labels) - 2 else "source" if index == 1 else "context", "location": location})
    return nodes


def normalize_findings(findings: list[dict[str, Any]], inventory: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: dict[tuple[str, str, int], dict[str, Any]] = {}
    for original in findings:
        item = dict(original)
        original_type = item.get("type", "unknown")
        item["type"] = _canonical_type(original_type, item.get("title", ""))
        dedupe_type = item["type"] if item["type"] != "external_static_finding" else f"external:{item.get('title', 'unknown')}"
        key = (dedupe_type, item.get("file", ""), int(item.get("line", 0)))
        item["snippet"] = redact_secret_text(item.get("snippet", ""))
        item["evidence"] = redact_secret_text(item.get("evidence", ""))
        if item["type"] == "secret_exposure":
            item["secret_redacted"] = True
        item["cwe"] = {"sql_injection": "CWE-89", "command_injection": "CWE-78", "xss": "CWE-79", "path_traversal": "CWE-22", "secret_exposure": "CWE-798", "insecure_authentication": "CWE-287", "insecure_configuration": "CWE-16", "vulnerable_dependency": "CWE-1104"}.get(item["type"], "CWE-693")
        if item["type"] == "vulnerable_dependency":
            item["advisory"] = {"status": "triage-only", "cve": None, "note": "No advisory database is configured; no CVE is asserted."}
        item["sources"] = sorted(set(item.get("sources", []) + [item.get("source", "custom-scanner")]))
        item["source"] = item["sources"][0]
        item["scanner_sources"] = item["sources"]
        item["scanner_rule_ids"] = sorted(set(item.get("scanner_rule_ids", [])))
        item["scanner_confidence"] = item.get("confidence", 0.5)
        item["line_start"] = item.get("line")
        item["line_end"] = item.get("line")
        item["code_snippet"] = item.get("snippet", "")
        item["description"] = item.get("explanation", "")
        item["affected_component"] = item.get("file", "repository").split("/")[0]
        item["risk"] = _risk(item, inventory)
        item["risk_score"] = item["risk"]["score"]
        item["risk_breakdown"] = item["risk"]
        item["exploitability"] = item["risk"]["exploitability"]
        item["exposure"] = item["risk"]["external_exposure"]
        item["data_sensitivity"] = item["risk"]["data_sensitivity"]
        item["reachability"] = item["risk"]["reachability"]
        item["analyst_confidence"] = round(min(0.99, float(item.get("confidence", 0.5)) * 0.97), 2)
        item["evidence_refs"] = [{"file": item.get("file"), "line": item.get("line"), "snippet": item.get("snippet")}]
        item["analysis_layer"] = "evidence-backed local security analyst"
        item["verification_status"] = item.get("verification_status", "unverified")
        item["attack_path_id"] = f"path-{item.get('id')}"
        item["patch"] = None
        item["created_at"] = datetime.now(timezone.utc).isoformat()
        item["attack_path_nodes"] = _path_nodes(item)
        if key not in normalized:
            normalized[key] = item
        else:
            current = normalized[key]
            current["sources"] = sorted(set(current["sources"] + item["sources"]))
            current["scanner_sources"] = current["sources"]
            current["scanner_rule_ids"] = sorted(set(current.get("scanner_rule_ids", []) + item.get("scanner_rule_ids", [])))
            current["confidence"] = max(current.get("confidence", 0), item.get("confidence", 0))
            current["analyst_confidence"] = max(current.get("analyst_confidence", 0), item.get("analyst_confidence", 0))
            current["related_files"] = sorted(set(current.get("related_files", []) + item.get("related_files", [])))
            current["evidence_refs"].extend(item["evidence_refs"])
            current["source"] = current["sources"][0]
    return sorted(normalized.values(), key=lambda item: (-item["risk_score"], item.get("file", ""), item.get("line", 0)))


def build_security_graph(inventory: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def node(node_id: str, label: str, kind: str, detail: str = ""):
        nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind, "detail": detail, "finding_ids": []})

    api_routes = inventory.get("api_routes", [])
    for index, route in enumerate(api_routes[:10]):
        route_id = f"route-{index}"
        node(route_id, f"{route['method']} {route['path']}", "route", f"{route['file']}:{route['line']}")
    if inventory.get("authentication_files"):
        node("auth", "Authentication", "auth", ", ".join(inventory["authentication_files"][:2]))
    if inventory.get("database_files"):
        node("database", "Database", "database", ", ".join(inventory["database_files"][:2]))
    if inventory.get("configuration_files"):
        node("config", "Configuration", "config", ", ".join(inventory["configuration_files"][:2]))
    node("external", "External impact", "impact", "Potential user, data, or service impact")

    for finding in findings:
        finding_id = f"finding-{finding['id']}"
        node(finding_id, finding["title"], "finding", f"{finding['file']}:{finding['line']}")
        nodes[finding_id]["finding_ids"].append(finding["id"])
        if api_routes:
            edges.append({"from": "route-0", "to": finding_id, "label": "reaches"})
        elif finding["type"] == "secret_exposure":
            edges.append({"from": "config", "to": finding_id, "label": "contains"})
        if finding["type"] in {"sql_injection", "vulnerable_dependency"}:
            node("database", "Database", "database")
            edges.append({"from": finding_id, "to": "database", "label": "touches"})
        elif finding["type"] in {"path_traversal", "secret_exposure"}:
            node("config", "Configuration", "config")
            edges.append({"from": finding_id, "to": "config", "label": "reads"})
        else:
            edges.append({"from": finding_id, "to": "external", "label": "impact"})

    return {"nodes": list(nodes.values()), "edges": edges[:80]}
