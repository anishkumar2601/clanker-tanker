# ClankerShield 0.2

ClankerShield is a hackathon-friendly repository security analyst for an evidence-backed remediation workflow:

`Repository → Analyze → Explain → Prioritize → Generate fix → Review diff → Apply → Rescan → Verify`

The current release keeps analysis local to the workspace. Deterministic scanners and repository inventory are the source of truth; the local analyst layer correlates evidence, explains impact, maps attack paths, and proposes a safe minimal patch only where the code shape is known. Secrets are redacted before findings are returned to the UI.

## Project structure

```text
.
├── backend/
│   ├── app/main.py          # FastAPI API, orchestration, patcher, verification
│   ├── app/inventory.py     # Repository inventory and evidence context
│   └── app/security_analysis.py # Secret scan, normalization, risk, graph
│   ├── requirements.txt
│   ├── run.py
│   └── .env.example
├── frontend/
│   ├── src/main.jsx         # React dashboard and workflow
│   ├── src/styles.css
│   ├── package.json
│   └── vite.config.js
└── demo-repository/         # reference fixture; the API creates an isolated copy at runtime
```

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Optional external scanners are detected at runtime. Install them separately when available:

```powershell
pip install semgrep bandit
```

If either executable is missing, the scan reports `Not installed` and continues with built-in analysis. For model-backed contextual analysis, set `CLANKER_AI_API_KEY` plus the optional `CLANKER_AI_BASE_URL` and `CLANKER_AI_MODEL` values from `backend/.env.example`. Without a key, the contextual bar uses clearly labeled deterministic local evidence.

The API runs at `http://127.0.0.1:8000`. Health check: `http://127.0.0.1:8000/api/health`.

### Frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

### Tests

From the project root:

```powershell
python -m unittest discover backend/tests -v
```

Optional frontend API override:

```text
VITE_API_BASE=http://127.0.0.1:8000/api
```

## Demo flow (about 3 minutes)

1. Open the frontend and choose **Launch demo repository**.
2. Point out the score, severity cards, files analyzed, and prioritized findings.
3. Select **SQL injection risk**. Show the scanner evidence, explanation, impact, and data-flow path.
4. Click **Generate safe fix** and review the unified diff.
5. Click **Apply approved patch**. The API checks the file hash so a stale diff cannot silently overwrite a changed file.
6. Click **Verify with rescan**. Show before/after counts, fixed findings, real security rescan status, and static syntax status.
7. Upload a ZIP of a small repository to show the same flow on user-provided code.

## 0.2 upgrade highlights

- Repository inventory: languages, frameworks, package managers, entry points, API routes, auth/data/config files, dependencies, tests, and sensitive files.
- Multi-layer local analysis: built-in rules, dependency triage, and a dedicated secret scanner for AWS/GitHub/JWT/private-key/database-URL/credential-shaped values.
- Secret redaction: secret-shaped snippets are masked before returning findings or exposing evidence in the UI.
- Finding normalization: overlapping hardcoded-secret and secret-scanner results are correlated into one finding with sources, CWE, evidence refs, verification status, and related components.
- Deterministic risk assessment: severity, exploitability, exposure, data sensitivity, reachability, evidence strength, and confidence produce an explainable risk score.
- Actual evidence paths: attack-path nodes include file/line references when the local evidence supports them.
- Scan progress: inventory, dependency, static, secret, correlation, analyst, and attack-path stages are returned by the API and shown in the dashboard.
- Security graph: inventory and findings are represented as clickable route/finding/system nodes.
- Security diff: after an approved patch and a real rescan, resolved and remaining findings are compared with before/after counts and scores.

## Security boundaries in this MVP

- ZIP uploads are size-limited, reject absolute paths, `..` traversal, and symlinks, and extract into an isolated workspace directory.
- Repository code is never executed by the default workflow. Verification compiles Python source in memory for syntax checking and deliberately reports runtime tests as `NOT_RUN`.
- Uploaded tests are not run on the host. Use an isolated CI/container runner for runtime tests in a production version.
- No repository file contents or secrets are written to application logs.
- Patch application requires an explicit user action and a matching pre-patch file hash.
- Semgrep and Bandit are optional subprocess scanners with timeouts and honest availability states; built-in analysis continues if they are unavailable.

## Environment variables

`backend/.env.example` documents runtime-test and optional AI-provider settings. `CLANKER_ENABLE_TEST_EXECUTION` is intentionally not used to run code in this MVP; it is a placeholder for wiring an isolated executor later.

## Known limitations and next steps

- The scanner uses deterministic rules plus optional Semgrep/Bandit adapters. Dependency findings remain triage-only until a real advisory database is configured; no CVE is asserted without advisory data.
- Generated patches target a small set of known-safe code shapes. Unsupported findings keep remediation guidance but do not receive an automatic patch.
- The API uses in-memory state and per-process temporary workspaces. SQLite persistence, authentication, and cleanup jobs should be added before multi-user deployment.
- Runtime test execution should be implemented in a locked-down container with no network, a read-only base image, CPU/memory/time limits, and an explicit command allowlist.
- The model provider is OpenAI-compatible and opt-in through environment variables; production should add a managed provider adapter and a sandboxed runtime executor.
