from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


EXCLUDED_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".clankershield"}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not any(part in EXCLUDED_PARTS for part in path.parts):
            yield path


def _read(path: Path, limit: int = 700_000) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def _language(path: Path) -> str:
    return {
        ".py": "Python", ".js": "JavaScript", ".jsx": "React / JSX", ".ts": "TypeScript", ".tsx": "React / TSX",
        ".go": "Go", ".java": "Java", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust", ".sql": "SQL",
        ".json": "JSON", ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML", ".env": "Environment",
    }.get(path.suffix.lower(), "Other")


def _add_unique(items: list[Any], value: Any, key: str | None = None) -> None:
    if key is None:
        if value not in items:
            items.append(value)
        return
    if not any(item.get(key) == value.get(key) for item in items if isinstance(item, dict)):
        items.append(value)


def _dependencies(path: Path, text: str) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    relative = path.as_posix().lower()
    if path.name == "package.json":
        try:
            document = json.loads(text)
            for group in ("dependencies", "devDependencies", "peerDependencies"):
                for name, version in document.get(group, {}).items():
                    dependencies.append({"name": name, "version": str(version), "kind": group})
        except (json.JSONDecodeError, AttributeError):
            pass
    elif path.name in {"requirements.txt", "requirements-dev.txt"} or "requirements" in relative:
        for line in text.splitlines():
            match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(?:([=!~<>]+)\s*([^\s;]+))?", line)
            if match and not line.lstrip().startswith("#"):
                dependencies.append({"name": match.group(1), "version": match.group(3) or "un pinned", "kind": "requirements"})
    elif path.name == "go.mod":
        for line in text.splitlines():
            match = re.match(r"^\s*([A-Za-z0-9./_-]+)\s+(v[^\s]+)", line)
            if match:
                dependencies.append({"name": match.group(1), "version": match.group(2), "kind": "go.mod"})
    return dependencies[:80]


def build_inventory(root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    language_counts: dict[str, int] = {}
    frameworks: list[str] = []
    package_managers: list[str] = []
    entry_points: list[str] = []
    api_routes: list[dict[str, Any]] = []
    auth_files: list[str] = []
    database_files: list[str] = []
    configuration_files: list[str] = []
    environment_files: list[str] = []
    test_directories: list[str] = []
    sensitive_files: list[str] = []
    dependencies: list[dict[str, str]] = []

    for path in _iter_files(root):
        relative = path.relative_to(root).as_posix()
        language = _language(path)
        language_counts[language] = language_counts.get(language, 0) + 1
        files.append({"path": relative, "language": language, "bytes": path.stat().st_size})
        lower = relative.lower()
        name = path.name.lower()
        text = _read(path)

        if name in {"requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "cargo.toml", "pom.xml", "gemfile"}:
            package_managers.append({"requirements.txt": "pip", "requirements-dev.txt": "pip", "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "go.mod": "go", "cargo.toml": "cargo", "pom.xml": "maven", "gemfile": "bundler"}.get(name, name))
        if name in {"main.py", "app.py", "server.py", "index.js", "server.js", "main.go", "manage.py"} or lower.endswith("/main.ts"):
            entry_points.append(relative)
        if name.startswith(".env") or name in {"credentials", "credentials.json", "secrets.json"}:
            environment_files.append(relative)
        if name.endswith((".yml", ".yaml", ".toml", ".ini", ".cfg")) or "config" in name or name in {"dockerfile", "nginx.conf"}:
            configuration_files.append(relative)
        if any(token in lower for token in ("auth", "login", "jwt", "session", "permission", "security")):
            auth_files.append(relative)
        if any(token in lower for token in ("db", "database", "model", "schema", "migration")):
            database_files.append(relative)
        if "/test" in f"/{lower}" or lower.startswith("test/") or "/tests/" in f"/{lower}" or name.startswith("test_"):
            test_directories.append(relative.split("/")[0] if "/" in relative else relative)
        if name.endswith((".pem", ".key")) or "secret" in name or "credential" in name or name == "id_rsa":
            sensitive_files.append(relative)
        if text is None:
            continue

        lower_text = text.lower()
        if any(token in lower_text for token in ("fastapi", "from fastapi")):
            frameworks.append("FastAPI")
        if "flask" in lower_text:
            frameworks.append("Flask")
        if "django" in lower_text:
            frameworks.append("Django")
        if "express" in lower_text:
            frameworks.append("Express")
        if "next/" in lower_text or "nextjs" in lower_text:
            frameworks.append("Next.js")
        if any(token in lower_text for token in ("sqlite", "postgres", "mysql", "mongodb", "redis", "cursor.execute", "connection.execute")):
            _add_unique(database_files, relative)

        for line_number, line in enumerate(text.splitlines(), start=1):
            route = re.search(r"(?:@(?:app|router)\.(get|post|put|patch|delete)|(?:app|router)\.(get|post|put|patch|delete))\s*\(\s*[\"']([^\"']+)", line, re.I)
            if route:
                _add_unique(api_routes, {"method": route.group(1).upper(), "path": route.group(2), "file": relative, "line": line_number}, "file")

        dependencies.extend(_dependencies(path, text))

    for item in files:
        if item["path"].lower().endswith((".py", ".js", ".ts", ".go", ".java", ".rb", ".php")) and item["path"] not in entry_points:
            continue

    return {
        "files": sorted(files, key=lambda item: item["path"]),
        "files_analyzed": len(files),
        "languages": language_counts,
        "frameworks": sorted(set(frameworks)),
        "package_managers": sorted(set(package_managers)),
        "entry_points": sorted(set(entry_points)),
        "api_routes": api_routes[:40],
        "authentication_files": sorted(set(auth_files))[:40],
        "database_files": sorted(set(database_files))[:40],
        "configuration_files": sorted(set(configuration_files))[:40],
        "environment_files": sorted(set(environment_files))[:40],
        "dependencies": dependencies[:120],
        "test_directories": sorted(set(test_directories))[:20],
        "sensitive_files": sorted(set(sensitive_files))[:30],
    }

