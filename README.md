# 🩹 Patch

Self-hosted dependency vulnerability watcher. Patch scans your local repo checkouts, extracts their dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`), matches every pinned dependency against [OSV.dev](https://osv.dev)'s vulnerability database, and shows you which of your projects are carrying a vulnerable package — on one dashboard.

**Stack:** FastAPI · SQLAlchemy · PostgreSQL · Redis (OSV response cache) · Jinja2 dashboard · Docker Compose

## Quick start (Docker)

```sh
# Point REPOS_DIR at the directory containing the repos you want to scan
REPOS_DIR=~/MyProjects docker compose up --build
```

Open http://localhost:8000 and track a repo either way:

- **GitHub link** — paste `https://github.com/owner/repo`; manifests are fetched via the GitHub API, no checkout needed. Set `GITHUB_TOKEN` in the environment for private repos / higher rate limits.
- **Local folder** — click **Browse…** to pick a directory (inside Docker that's under `/repos`, the `REPOS_DIR` mount).

Then hit **Scan**.

## Local development

```sh
docker compose up -d db redis          # just the databases
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
.venv/bin/python -m pytest             # run tests
```

When running outside Docker, use real host paths (e.g. `~/MyProjects/my-api`) when tracking repos.

## How it works

1. **Ingestion** — you register a repo by GitHub URL or local path. For local repos the scanner walks the tree (skipping `node_modules`, virtualenvs, etc.); for GitHub repos it lists the default branch's tree via the API and fetches just the manifest files. Either way manifests are parsed into normalized `{name, version, ecosystem}` deps. Only exactly-pinned versions are vulnerability-checked; npm `^`/`~` specs are approximated by their base version.
2. **Matching** — deps are sent to OSV.dev's `POST /v1/querybatch`, then each hit's details are fetched and summarized (CVE ID, severity, affected range, fixed version). All OSV responses are cached in Redis for 24h keyed by `name@version`, so re-scans only hit the network for what changed.
3. **Storage & diffing** — deps are upserted into Postgres keeping `first_seen_at`/`last_seen_at`; deps that disappear from manifests are pruned, and every scan is logged to `scan_history`.
4. **Dashboard** — per-repo dependency lists with flagged packages, plus a global all-vulnerabilities view sorted by severity.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/repos` | Tracked repos with dep/vuln counts |
| `POST` | `/api/repos` | Track a repo: `{"source": "<GitHub URL or local path>", "name"?}` |
| `GET` | `/api/browse?path=` | List subdirectories (backs the dashboard folder picker) |
| `GET` | `/api/repos/{id}/dependencies` | Dependencies + their vulnerabilities |
| `GET` | `/api/vulnerabilities` | All vulnerabilities, sorted by severity |
| `POST` | `/repos/{id}/scan` | Trigger a scan (send `Accept: application/json` for a JSON result) |

## Roadmap

- P1: scheduled re-scanning (APScheduler), scan diffing, alerting on new vulnerabilities
- P2: history/trend view, GitHub OAuth repo picker
- P3: more ecosystems, severity-based alert rules
