from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .ai_analyst import analyze_finding, answer_question, provider_status
from .external_scanners import run_bandit, run_semgrep
from .inventory import build_inventory
from .security_analysis import build_security_graph, normalize_findings, scan_secrets


APP_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = APP_ROOT / ".clankershield-data"
DATA_ROOT.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_FILES = 5_000
MAX_TEXT_FILE_BYTES = 1_500_000

app = FastAPI(title="ClankerShield API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPOSITORIES: dict[str, dict[str, Any]] = {}
PATCHES: dict[str, dict[str, Any]] = {}


class ApplyPatchRequest(BaseModel):
    patch_id: str


class QuestionRequest(BaseModel):
    question: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_id(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def json_safe_repo(repo: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in repo.items()
        if key not in {"root", "before_findings", "before_scan", "scan_snapshot", "last_scan", "verification"}
    }


def human_name(path: str) -> str:
    return Path(path).name or path


def line_number_for(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def language_for(path: Path) -> str:
    suffix = path.suffix.lower()
    return {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "React / JSX",
        ".ts": "TypeScript",
        ".tsx": "React / TSX",
        ".java": "Java",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".rs": "Rust",
        ".sql": "SQL",
        ".json": "JSON",
        ".yml": "YAML",
        ".yaml": "YAML",
        ".toml": "TOML",
        ".env": "Environment",
        ".html": "HTML",
    }.get(suffix, "Other")


def iter_source_files(root: Path):
    excluded = {".git", "node_modules", ".venv", "venv", "__pycache__", ".clankershield"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded for part in path.parts):
            continue
        yield path


def code_snippet(text: str, line: int, radius: int = 2) -> str:
    lines = text.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(
        f"{index + 1:>4}  {lines[index]}" for index in range(start, end)
    )


RULES = [
    {
        "type": "sql_injection",
        "title": "SQL injection risk",
        "severity": "Critical",
        "confidence": 0.98,
        "patterns": [
            re.compile(r"execute\s*\(\s*f[\"']", re.I),
            re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|\.format\(|%\s+)", re.I),
            re.compile(r"query\s*=\s*f[\"'].*(?:SELECT|INSERT|UPDATE|DELETE)", re.I),
        ],
        "explanation": "User-controlled data is being composed into a SQL statement before it reaches the database driver. The database sees structure and data in the same string, so crafted input can alter the intended query.",
        "impact": "An attacker could read, modify, or delete records accessible to the database account.",
        "remediation": "Use parameterized queries or the framework's query builder, and validate the input against the expected shape.",
        "attack_path": ["HTTP request", "User-controlled input", "Query construction", "Database driver", "Application database"],
    },
    {
        "type": "command_injection",
        "title": "Shell command injection risk",
        "severity": "Critical",
        "confidence": 0.96,
        "patterns": [
            re.compile(r"os\.system\s*\(", re.I),
            re.compile(r"shell\s*=\s*True", re.I),
        ],
        "explanation": "A shell command is built or launched through an API that can interpret attacker-controlled characters. The process boundary is not treating the input as a single argument.",
        "impact": "If reachable from an endpoint, an attacker may execute unintended commands with the service account's permissions.",
        "remediation": "Prefer an argument array with shell execution disabled. Apply strict allowlists for values that select an operation or host.",
        "attack_path": ["HTTP request", "Request parameter", "Shell command API", "Operating system process"],
    },
    {
        "type": "hardcoded_secret",
        "title": "Hardcoded credential or API key",
        "severity": "High",
        "confidence": 0.93,
        "patterns": [
            re.compile(r"(?:api[_-]?key|secret|password|token)\s*=\s*[\"'][^\"']{8,}[\"']", re.I),
        ],
        "explanation": "A credential-like value is stored directly in source code. Source code is commonly copied into version control, build artifacts, logs, and developer machines.",
        "impact": "Anyone who obtains the repository may be able to impersonate the application or access a third-party service.",
        "remediation": "Move the value to a secret manager or environment variable, rotate the exposed credential, and add secret scanning to CI.",
        "attack_path": ["Source repository", "Credential in source", "Build artifact or clone", "Third-party service"],
    },
    {
        "type": "xss",
        "title": "Unsafe HTML rendering",
        "severity": "High",
        "confidence": 0.9,
        "patterns": [re.compile(r"\.innerHTML\s*=", re.I), re.compile(r"dangerouslySetInnerHTML", re.I)],
        "explanation": "Data is inserted into an HTML context without visible output encoding or sanitization at the sink.",
        "impact": "A malicious value could execute script in another user's browser session.",
        "remediation": "Render text through the framework's escaped APIs, or sanitize HTML with a well-maintained allowlist before rendering.",
        "attack_path": ["HTTP request", "User-controlled value", "HTML sink", "Victim browser"],
    },
    {
        "type": "path_traversal",
        "title": "Potential path traversal",
        "severity": "High",
        "confidence": 0.88,
        "patterns": [
            re.compile(r"open\s*\([^\n]*(?:request\.|query|params)", re.I),
            re.compile(r"os\.path\.join\s*\([^\n]*(?:request\.|query|params)", re.I),
        ],
        "explanation": "A request-derived path appears to flow into file access without an evident containment check.",
        "impact": "An attacker may read or overwrite files outside the intended directory.",
        "remediation": "Resolve the candidate path and verify it remains inside a trusted base directory before opening it.",
        "attack_path": ["HTTP request", "Filename parameter", "Path join", "Filesystem"],
    },
    {
        "type": "insecure_authentication",
        "title": "Authentication check is weakened",
        "severity": "High",
        "confidence": 0.94,
        "patterns": [
            re.compile(r"verify_signature\s*=\s*False", re.I),
            re.compile(r"(?:md5|sha1)\s*\(", re.I),
        ],
        "explanation": "The code disables a security verification or uses a legacy primitive in an authentication-sensitive context.",
        "impact": "Tokens or passwords may be forged, replayed, or cracked more easily than intended.",
        "remediation": "Keep signature verification enabled and use a modern password hashing/KDF implementation with an appropriate work factor.",
        "attack_path": ["Client credential", "Authentication helper", "Disabled verification", "Protected route"],
    },
    {
        "type": "insecure_configuration",
        "title": "Insecure production configuration",
        "severity": "Medium",
        "confidence": 0.97,
        "patterns": [
            re.compile(r"\bDEBUG\s*=\s*True\b", re.I),
            re.compile(r"allow_origins\s*=\s*\[[^\]]*[\"']\*[\"']", re.I),
        ],
        "explanation": "A development-oriented setting or unrestricted browser origin is enabled in configuration that may be deployed.",
        "impact": "Debug details or cross-origin access can expose sensitive information and widen the attack surface.",
        "remediation": "Disable debug mode in production and set an explicit allowlist of trusted origins.",
        "attack_path": ["Deployment configuration", "Overly broad setting", "Application response", "Untrusted client"],
    },
]

DEPENDENCY_RULE = {
    "type": "vulnerable_dependency",
    "title": "Dependency version requires review",
    "severity": "Medium",
    "confidence": 0.8,
    "explanation": "The dependency manifest pins an old release family with known security maintenance concerns. This is a triage signal, not a substitute for an advisory database review.",
    "impact": "Known vulnerabilities in a transitive or direct dependency may be reachable through application code.",
    "remediation": "Upgrade to a supported release, review the changelog, and lock the resulting dependency tree in CI.",
    "attack_path": ["Dependency manifest", "Old package", "Application import", "Runtime behavior"],
}


def match_rule(rule: dict[str, Any], line: str) -> re.Match[str] | None:
    for pattern in rule["patterns"]:
        match = pattern.search(line)
        if match:
            return match
    return None


def scan_repository(repo: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    root = Path(repo["root"])
    findings: list[dict[str, Any]] = []
    files_analyzed = 0
    languages: dict[str, int] = {}
    stage_records: dict[str, dict[str, Any]] = {}

    def begin_stage() -> tuple[float, str]:
        return time.perf_counter(), now_iso()

    def finish_stage(stage_id: str, label: str, marker: tuple[float, str], status: str, result_count: int, error: str | None = None, detail: str = "") -> None:
        clock, started_iso = marker
        stage_records[stage_id] = {
            "id": stage_id,
            "label": label,
            "status": status,
            "started_at": started_iso,
            "ended_at": now_iso(),
            "duration_ms": round((time.perf_counter() - clock) * 1000),
            "result_count": result_count,
            "error": error,
            "detail": detail,
        }

    static_stage = begin_stage()
    for path in iter_source_files(root):
        relative = path.relative_to(root).as_posix()
        text = read_text(path)
        if text is None:
            continue
        files_analyzed += 1
        language = language_for(path)
        languages[language] = languages.get(language, 0) + 1

        for line_index, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                match = match_rule(rule, line)
                if not match:
                    continue
                finding_key = f"{rule['type']}|{relative}|{line_index}"
                finding_id = make_id(finding_key)
                if any(existing["id"] == finding_id for existing in findings):
                    continue
                findings.append(
                    {
                        "id": finding_id,
                        "type": rule["type"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "source": "pattern-scanner",
                        "file": relative,
                        "line": line_index,
                        "snippet": code_snippet(text, line_index),
                        "evidence": line.strip(),
                        "explanation": rule["explanation"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "related_files": [],
                        "attack_path": rule["attack_path"],
                        "patch_available": rule["type"] in {"sql_injection", "command_injection", "hardcoded_secret", "insecure_configuration", "vulnerable_dependency"},
                    }
                )

        if path.name.lower() in {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json"}:
            for line_index, line in enumerate(text.splitlines(), start=1):
                if re.search(r"(?:requests|flask|django|express)\s*(?:==|:)\s*(?:1\.|2\.0|2\.1|2\.2|4\.0)", line, re.I):
                    finding_key = f"vulnerable_dependency|{relative}|{line_index}"
                    findings.append(
                        {
                            "id": make_id(finding_key),
                            "type": DEPENDENCY_RULE["type"],
                            "title": DEPENDENCY_RULE["title"],
                            "severity": DEPENDENCY_RULE["severity"],
                            "confidence": DEPENDENCY_RULE["confidence"],
                            "source": "dependency-triage",
                            "file": relative,
                            "line": line_index,
                            "snippet": code_snippet(text, line_index),
                            "evidence": line.strip(),
                            "explanation": DEPENDENCY_RULE["explanation"],
                            "impact": DEPENDENCY_RULE["impact"],
                            "remediation": DEPENDENCY_RULE["remediation"],
                            "related_files": [],
                            "attack_path": DEPENDENCY_RULE["attack_path"],
                            "patch_available": True,
                        }
                    )

    finish_stage("static", "Static analysis", static_stage, "completed", len(findings), detail="Built-in rules evaluated")

    inventory_stage = begin_stage()
    inventory = build_inventory(root)
    finish_stage("inventory", "Repository inventory", inventory_stage, "completed", inventory["files_analyzed"], detail=f"{inventory['files_analyzed']} files mapped")

    dependency_stage = begin_stage()
    finish_stage("dependencies", "Dependency analysis", dependency_stage, "completed", len(inventory["dependencies"]), detail=f"{len(inventory['dependencies'])} dependencies catalogued; advisory lookup is not asserted")

    semgrep = run_semgrep(root)
    stage_records["semgrep"] = {
        "id": "semgrep", "label": "Semgrep", "status": "warning" if semgrep["status"] == "not_installed" else semgrep["status"],
        "started_at": semgrep["started_at"], "ended_at": semgrep["ended_at"], "duration_ms": semgrep["duration_ms"],
        "result_count": len(semgrep["findings"]), "error": semgrep["error"],
        "detail": "Available and completed" if semgrep["status"] == "completed" else ("Not installed; built-in analysis retained" if semgrep["status"] == "not_installed" else semgrep["error"] or "Optional scanner failed"),
    }
    findings.extend(semgrep["findings"])

    bandit = run_bandit(root)
    stage_records["bandit"] = {
        "id": "bandit", "label": "Bandit", "status": "warning" if bandit["status"] == "not_installed" else bandit["status"],
        "started_at": bandit["started_at"], "ended_at": bandit["ended_at"], "duration_ms": bandit["duration_ms"],
        "result_count": len(bandit["findings"]), "error": bandit["error"],
        "detail": "Available and completed" if bandit["status"] == "completed" else ("Not installed; built-in analysis retained" if bandit["status"] == "not_installed" else bandit["error"] or "Optional scanner failed"),
    }
    findings.extend(bandit["findings"])

    secret_stage = begin_stage()
    secret_findings = scan_secrets(root)
    findings.extend(secret_findings)
    finish_stage("secrets", "Secret detection", secret_stage, "completed", len(secret_findings), detail="Redacted output enforced")

    correlation_stage = begin_stage()
    findings = normalize_findings(findings, inventory)
    finish_stage("correlation", "Finding correlation", correlation_stage, "completed", len(findings), detail="Duplicate scanner evidence merged")
    evidence_stage = begin_stage()
    finish_stage("evidence", "Evidence extraction", evidence_stage, "completed", sum(1 for item in findings if item.get("evidence_refs")), detail="File and line references are local")
    risk_stage = begin_stage()
    finish_stage("risk", "Risk analysis", risk_stage, "completed", len(findings), detail="Deterministic factors calculated")
    ai = provider_status()
    ai_stage = begin_stage()
    finish_stage("analysis", "AI security reasoning", ai_stage, "available_on_demand" if ai["status"] == "available" else "not_configured", 0, detail=ai["message"])
    path_stage = begin_stage()
    graph = build_security_graph(inventory, findings)
    finish_stage("paths", "Attack-path analysis", path_stage, "completed", sum(1 for item in findings if item.get("attack_path_nodes")), detail="Paths labeled from available evidence")

    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in ["Critical", "High", "Medium", "Low"]}
    score = max(0, min(100, 100 - counts["Critical"] * 24 - counts["High"] * 13 - counts["Medium"] * 6 - counts["Low"] * 2))
    duration_ms = round((time.perf_counter() - started) * 1000)
    ordered_stage_ids = ["inventory", "dependencies", "semgrep", "bandit", "static", "secrets", "correlation", "evidence", "risk", "analysis", "paths"]
    stages = [stage_records[stage_id] for stage_id in ordered_stage_ids if stage_id in stage_records]
    public_runs = {name: {key: value for key, value in run.items() if key not in {"stdout", "stderr"}} for name, run in {"semgrep": semgrep, "bandit": bandit}.items()}
    result = {
        "findings": findings,
        "counts": counts,
        "score": score,
        "files_analyzed": inventory["files_analyzed"],
        "languages": inventory["languages"],
        "inventory": inventory,
        "stages": stages,
        "scanner_runs": public_runs,
        "graph": graph,
        "scanner_sources": sorted(set(["pattern-scanner", "secret-scanner", "dependency-triage"] + [name for name, run in (("semgrep", semgrep), ("bandit", bandit)) if run["status"] == "completed"])),
        "ai": ai,
        "ai_summary": {
            "mode": "evidence-backed analyst with optional model provider",
            "confirmed_findings": len(findings),
            "hypotheses": 0,
            "explanation": "The deterministic system owns scanner truth, file references, risk, and verification. Model analysis is opt-in and receives only redacted structured evidence.",
        },
        "duration_ms": duration_ms,
        "scanned_at": now_iso(),
    }
    repo["scan_snapshot"] = result
    repo["last_scan"] = result
    return result


def demo_files() -> dict[str, str]:
    return {
        "app/config.py": """import os\n\n# Demo-only configuration fixture\nDEBUG = True\nSTRIPE_API_KEY = \"sk_live_demo_not_a_real_credential\"\nALLOWED_ORIGINS = [\"*\"]\n""",
        "app/routes.py": """import os\nimport sqlite3\nimport subprocess\n\n\ndef search_users(username: str):\n    # Intentional demo finding: user input is interpolated into SQL.\n    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n    connection = sqlite3.connect(\"demo.db\")\n    return connection.execute(query).fetchall()\n\n\ndef ping_host(host: str):\n    # Intentional demo finding: shell command is assembled from input.\n    os.system(\"echo Pinging \" + host)\n""",
        "requirements.txt": "flask==1.0.0\nrequests==2.19.0\n",
        "tests/test_smoke.py": """def test_demo_fixture_is_present():\n    assert True\n""",
        "README.md": """# ClankerShield Demo Repository\n\nThis repository is a harmless local fixture for demonstrating static security analysis.\nThe snippets do not call external services.\n""",
    }


def write_demo_repository() -> Path:
    root = Path(tempfile.mkdtemp(prefix="clankershield-demo-", dir=DATA_ROOT))
    for relative, content in demo_files().items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def make_repo(name: str, root: Path, source: str) -> dict[str, Any]:
    repo_id = uuid.uuid4().hex[:10]
    repo = {
        "id": repo_id,
        "name": name,
        "source": source,
        "root": str(root),
        "created_at": now_iso(),
        "status": "ready",
        "last_scan": None,
        "before_findings": None,
    }
    REPOSITORIES[repo_id] = repo
    return repo


def get_repo(repo_id: str) -> dict[str, Any]:
    repo = REPOSITORIES.get(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


def safe_extract_zip(payload: bytes, destination: Path) -> None:
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="ZIP exceeds the 25 MB upload limit")
    destination.mkdir(parents=True, exist_ok=True)
    # Re-open from bytes without persisting the uploaded archive to logs or a public path.
    import io

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) > MAX_FILES:
                raise HTTPException(status_code=413, detail="ZIP contains too many files")
            total_size = sum(item.file_size for item in members)
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise HTTPException(status_code=413, detail="ZIP expands beyond the 100 MB safety limit")
            for member in members:
                name = member.filename.replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in Path(name).parts:
                    raise HTTPException(status_code=400, detail="ZIP contains an unsafe path")
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise HTTPException(status_code=400, detail="ZIP symlinks are not accepted")
                target = (destination / name).resolve()
                if destination.resolve() not in target.parents:
                    raise HTTPException(status_code=400, detail="ZIP path escapes extraction directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    extracted_bytes = 0
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        extracted_bytes += len(chunk)
                        if extracted_bytes > MAX_UNCOMPRESSED_BYTES:
                            raise HTTPException(status_code=413, detail="ZIP expands beyond the 100 MB safety limit")
                        output.write(chunk)
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid ZIP archive") from exc


def find_finding(repo: dict[str, Any], finding_id: str) -> dict[str, Any]:
    findings = (repo.get("last_scan") or {}).get("findings", [])
    for finding in findings:
        if finding["id"] == finding_id:
            return finding
    raise HTTPException(status_code=404, detail="Finding not found in the latest scan")


def generate_fixed_text(finding: dict[str, Any], current: str) -> tuple[str, str] | None:
    kind = finding["type"]
    if kind == "sql_injection":
        updated = re.sub(
            r"query\s*=\s*f[\"']SELECT \* FROM users WHERE name = '\{username\}'[\"']",
            'query = "SELECT * FROM users WHERE name = ?"',
            current,
        )
        updated = updated.replace("connection.execute(query).fetchall()", "connection.execute(query, (username,)).fetchall()")
        if updated != current:
            return updated, "Replaced string interpolation with a parameterized query and passed the value separately to the database driver."
    elif kind == "command_injection":
        updated = current.replace('os.system("echo Pinging " + host)', 'subprocess.run(["echo", "Pinging", host], check=True, shell=False)')
        if updated != current:
            return updated, "Replaced shell string concatenation with an argument array and explicitly disabled shell interpretation."
    elif kind in {"hardcoded_secret", "secret_exposure"} and finding.get("patch_available"):
        match = re.search(r"(?m)^(\s*)([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)\s*=\s*[\"'][^\"']+[\"']\s*$", current)
        if match:
            variable = match.group(2)
            replacement = f'{match.group(1)}{variable} = os.getenv("{variable}")'
            updated = current[: match.start()] + replacement + current[match.end() :]
            if updated != current:
                return updated, "Moved the credential lookup to an environment variable so the secret is not stored in source control."
    elif kind == "insecure_configuration":
        updated = re.sub(r"\bDEBUG\s*=\s*True\b", "DEBUG = False", current)
        updated = re.sub(r"allow_origins\s*=\s*\[[^\]]*[\"']\*[\"']\]", 'allow_origins = ["https://example.com"]', updated, flags=re.I)
        updated = re.sub(r"ALLOWED_ORIGINS\s*=\s*\[[^\]]*[\"']\*[\"']\]", 'ALLOWED_ORIGINS = ["https://example.com"]', updated, flags=re.I)
        if updated != current:
            return updated, "Disabled debug behavior and narrowed the browser-origin policy to an explicit allowlist."
    elif kind == "vulnerable_dependency":
        updated = re.sub(r"(?im)^(flask|requests|django)(==|:)[^\s]+", lambda m: f"{m.group(1)}>=2.32.0" if m.group(1).lower() == "requests" else f"{m.group(1)}>=3.0.0", current)
        if updated != current:
            return updated, "Moved the dependency to a maintained release family; the lockfile and advisory review should still be completed in CI."
    return None


def make_diff(relative: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        )
    )


def safe_static_verification(root: Path) -> dict[str, Any]:
    python_files = list(root.rglob("*.py"))
    syntax_errors: list[str] = []
    # compile() checks syntax without importing or executing repository code.
    for path in python_files:
        text = read_text(path)
        if text is None:
            continue
        try:
            compile(text, str(path), "exec")
        except SyntaxError as exc:
            syntax_errors.append(f"{path.name}:{exc.lineno}: {exc.msg}")
    has_test_files = any(path.name.startswith("test_") or path.name.endswith("_test.py") for path in root.rglob("*"))
    return {
        "test_status": "NOT_RUN",
        "test_label": "Not run in safe mode",
        "test_reason": "Repository test commands are not executed on uploaded code by this MVP. Use an isolated CI runner for runtime tests.",
        "test_files_detected": has_test_files,
        "syntax_status": "PASS" if not syntax_errors else "FAIL",
        "syntax_errors": syntax_errors,
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "clankershield-api"}


@app.post("/api/repositories/demo")
def create_demo() -> dict[str, Any]:
    root = write_demo_repository()
    repo = make_repo("ClankerShield Demo Repository", root, "demo")
    scan_repository(repo)
    repo["before_findings"] = list(repo["last_scan"]["findings"])
    repo["before_scan"] = json.loads(json.dumps(repo["last_scan"]))
    return {"repository": json_safe_repo(repo), "scan": repo["last_scan"]}


@app.post("/api/repositories/upload")
async def upload_repository(file: UploadFile = File(...)) -> dict[str, Any]:
    filename = file.filename or "repository.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip repository archive")
    payload = await file.read()
    root = Path(tempfile.mkdtemp(prefix="clankershield-upload-", dir=DATA_ROOT))
    try:
        safe_extract_zip(payload, root)
    except HTTPException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    repo = make_repo(Path(filename).stem, root, "upload")
    scan_repository(repo)
    repo["before_findings"] = list(repo["last_scan"]["findings"])
    repo["before_scan"] = json.loads(json.dumps(repo["last_scan"]))
    return {"repository": json_safe_repo(repo), "scan": repo["last_scan"]}


@app.get("/api/repositories/{repo_id}")
def get_repository(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    return {"repository": json_safe_repo(repo), "scan": repo.get("last_scan")}


@app.post("/api/repositories/{repo_id}/scan")
def rescan_repository(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    return {"repository": json_safe_repo(repo), "scan": scan_repository(repo)}


@app.get("/api/repositories/{repo_id}/findings/{finding_id}")
def get_finding(repo_id: str, finding_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    return {"finding": find_finding(repo, finding_id)}


@app.post("/api/repositories/{repo_id}/findings/{finding_id}/analyze")
def analyze_finding_endpoint(repo_id: str, finding_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    finding = find_finding(repo, finding_id)
    scan = repo.get("last_scan") or scan_repository(repo)
    analysis = analyze_finding(finding, scan.get("inventory", {}), Path(repo["root"]))
    if analysis.get("status") == "completed" and analysis.get("analysis"):
        finding["ai_analysis"] = analysis["analysis"]
        finding["ai_confidence"] = analysis["analysis"].get("confidence")
    return {"analysis": analysis, "finding": finding}


@app.post("/api/repositories/{repo_id}/questions")
def repository_question(repo_id: str, request: QuestionRequest) -> dict[str, Any]:
    repo = get_repo(repo_id)
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Ask a question about the current repository")
    if len(question) > 500:
        raise HTTPException(status_code=400, detail="Question must be 500 characters or fewer")
    scan = repo.get("last_scan") or scan_repository(repo)
    return answer_question(question, scan, repo, Path(repo["root"]))


@app.post("/api/repositories/{repo_id}/findings/{finding_id}/fix")
def generate_fix(repo_id: str, finding_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    finding = find_finding(repo, finding_id)
    if not finding.get("patch_available"):
        raise HTTPException(status_code=422, detail="This finding has guidance but no safe MVP patch generator")
    path = Path(repo["root"]) / finding["file"]
    before = read_text(path)
    if before is None:
        raise HTTPException(status_code=422, detail="The affected file is not a readable text file")
    result = generate_fixed_text(finding, before)
    if not result:
        raise HTTPException(status_code=422, detail="No safe minimal patch is available for this code shape")
    after, explanation = result
    changed_lines = sum(1 for line in make_diff(finding["file"], before, after).splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
    patch_id = uuid.uuid4().hex[:12]
    patch = {
        "id": patch_id,
        "repo_id": repo_id,
        "finding_id": finding_id,
        "file": finding["file"],
        "before": before,
        "after": after,
        "diff": make_diff(finding["file"], before, after),
        "explanation": explanation,
        "base_hash": hashlib.sha256(before.encode("utf-8")).hexdigest(),
        "changed_files": [finding["file"]],
        "lines_changed": changed_lines,
        "safety_checks": {"single_file": True, "expected_content_hash": True, "generated_from_current_scan": True},
        "created_at": now_iso(),
        "status": "draft",
    }
    PATCHES[patch_id] = patch
    return {"patch": {key: value for key, value in patch.items() if key not in {"before", "after"}}}


@app.post("/api/repositories/{repo_id}/patches/apply")
def apply_patch(repo_id: str, request: ApplyPatchRequest) -> dict[str, Any]:
    repo = get_repo(repo_id)
    patch = PATCHES.get(request.patch_id)
    if not patch or patch["repo_id"] != repo_id:
        raise HTTPException(status_code=404, detail="Patch draft not found")
    if patch.get("status") != "draft":
        raise HTTPException(status_code=409, detail="Patch is no longer in a reviewable draft state")
    root = Path(repo["root"]).resolve()
    path = (root / patch["file"]).resolve()
    if root not in path.parents or path == root:
        raise HTTPException(status_code=400, detail="Patch target is outside the repository")
    if patch.get("changed_files") != [patch["file"]] or not patch.get("safety_checks", {}).get("single_file"):
        raise HTTPException(status_code=422, detail="Patch scope is not limited to one reviewed file")
    current = read_text(path)
    if current is None:
        raise HTTPException(status_code=422, detail="The affected file is no longer readable")
    current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
    if current_hash != patch["base_hash"]:
        raise HTTPException(status_code=409, detail="File changed since the diff was generated; rescan before applying")
    backup_dir = root / ".clankershield" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    (backup_dir / f"{patch['id']}-{Path(patch['file']).name}.before").write_text(current, encoding="utf-8")
    path.write_text(patch["after"], encoding="utf-8")
    patch["status"] = "applied"
    return {"status": "applied", "patch": {key: value for key, value in patch.items() if key not in {"before", "after"}}}


@app.post("/api/repositories/{repo_id}/verify")
def verify_repository(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    before_scan = repo.get("before_scan") or (repo.get("last_scan") or {})
    before = before_scan.get("findings", [])
    after = scan_repository(repo)
    before_ids = {finding["id"] for finding in before}
    after_ids = {finding["id"] for finding in after["findings"]}
    fixed = len(before_ids - after_ids)
    resolved = [dict(finding, verification_status="verified_fixed") for finding in before if finding["id"] not in after_ids]
    remaining = [dict(finding, verification_status="remaining") for finding in after["findings"]]
    after["findings"] = remaining
    after["resolved_findings"] = resolved
    before_counts = {severity: sum(1 for item in before if item["severity"] == severity) for severity in ["Critical", "High", "Medium", "Low"]}
    after_counts = {severity: sum(1 for item in remaining if item["severity"] == severity) for severity in ["Critical", "High", "Medium", "Low"]}
    verification = safe_static_verification(Path(repo["root"]))
    verification.update(
        {
            "before_count": len(before),
            "after_count": len(remaining),
            "fixed_count": fixed,
            "remaining_count": len(remaining),
            "security_rescan": "PASS" if not (before_ids & after_ids) else "FAIL",
            "original_finding_status": "CLEARED" if not (before_ids & after_ids) else "STILL DETECTED",
            "runtime_status": "NOT_AVAILABLE",
            "final_verdict": "VERIFIED" if fixed > 0 and not (before_ids & after_ids) and verification.get("syntax_status") == "PASS" else "FAILED" if (before_ids & after_ids) or verification.get("syntax_status") == "FAIL" else "NOT_VERIFIED",
            "score_before": before_scan.get("score", 0),
            "score_after": after["score"],
            "before_counts": before_counts,
            "after_counts": after_counts,
            "resolved_findings": resolved,
            "remaining_findings": remaining,
            "verified_at": now_iso(),
        }
    )
    after["security_diff"] = {
        "before": {"counts": before_counts, "total": len(before), "score": before_scan.get("score", 0)},
        "after": {"counts": after_counts, "total": len(remaining), "score": after["score"]},
        "resolved": resolved,
        "remaining": remaining,
    }
    repo["verification"] = verification
    return {"verification": verification, "scan": after}


@app.get("/api/repositories/{repo_id}/structure")
def repository_structure(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    root = Path(repo["root"])
    files = []
    for path in iter_source_files(root):
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "language": language_for(path), "bytes": path.stat().st_size})
    return {"files": sorted(files, key=lambda item: item["path"])}


@app.get("/api/repositories/{repo_id}/inventory")
def repository_inventory(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    scan = repo.get("last_scan") or scan_repository(repo)
    return {"inventory": scan.get("inventory", {})}


@app.get("/api/repositories/{repo_id}/graph")
def repository_graph(repo_id: str) -> dict[str, Any]:
    repo = get_repo(repo_id)
    scan = repo.get("last_scan") or scan_repository(repo)
    return {"graph": scan.get("graph", {"nodes": [], "edges": []})}
