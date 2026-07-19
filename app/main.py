import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from app import config
from app.auth import AuthRequired, current_user, router as auth_router
from app.db import Base, engine, get_session
from app.github import GitHubError, parse_github_url
from app.models import Dependency, Repo, User, Vulnerability
from app.osv import OSVClient
from app.risk import explain_risk
from app.scanner import scan_repo
from app.templating import severity_rank, templates

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    for attempt in range(30):
        try:
            Base.metadata.create_all(engine)
            break
        except OperationalError:
            logger.info("Waiting for Postgres... (%d)", attempt)
            time.sleep(1)
    else:
        raise RuntimeError("Postgres never became available")
    app.state.osv = OSVClient()
    yield


app = FastAPI(title="Patch", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware, secret_key=config.SECRET_KEY, same_site="lax"
)
app.include_router(auth_router)


@app.exception_handler(AuthRequired)
async def auth_required_handler(request: Request, _exc: AuthRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


def repo_summary(repo: Repo) -> dict:
    vulns = [v for d in repo.dependencies for v in d.vulnerabilities]
    highest = max((v.severity for v in vulns), key=severity_rank, default=None)
    return {
        "repo": repo,
        "dependency_count": len(repo.dependencies),
        "vulnerable_count": sum(1 for d in repo.dependencies if d.vulnerabilities),
        "highest_severity": highest,
    }


def _load_repos(session: Session, user: User) -> list[Repo]:
    return list(
        session.scalars(
            select(Repo)
            .where(Repo.user_id == user.id)
            .options(selectinload(Repo.dependencies).selectinload(Dependency.vulnerabilities))
            .order_by(Repo.name)
        )
    )


def _get_repo(session: Session, user: User, repo_id: int) -> Repo:
    repo = session.get(Repo, repo_id)
    if repo is None or repo.user_id != user.id:
        raise HTTPException(404, "Repo not found")
    return repo


def _user_vulns(session: Session, user: User) -> list[Vulnerability]:
    return list(
        session.scalars(
            select(Vulnerability)
            .join(Vulnerability.dependency)
            .join(Dependency.repo)
            .where(Repo.user_id == user.id)
            .options(
                selectinload(Vulnerability.dependency).selectinload(Dependency.repo)
            )
        )
    )


# ---------- Dashboard pages ----------

@app.get("/")
def index(
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    summaries = [repo_summary(r) for r in _load_repos(session, user)]
    return templates.TemplateResponse(
        request, "index.html", {"user": user, "summaries": summaries}
    )


@app.get("/repos/{repo_id}")
def repo_detail(
    repo_id: int,
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    repo = _get_repo(session, user, repo_id)
    flagged = sorted(
        (d for d in repo.dependencies if d.vulnerabilities),
        key=lambda d: (
            -max(severity_rank(v.severity) for v in d.vulnerabilities),
            d.name,
        ),
    )
    for d in flagged:
        d.vulnerabilities.sort(key=lambda v: -severity_rank(v.severity))
    clean = sorted(
        (d for d in repo.dependencies if not d.vulnerabilities and d.version),
        key=lambda d: d.name,
    )
    unchecked = sorted(
        (d for d in repo.dependencies if not d.version), key=lambda d: d.name
    )
    return templates.TemplateResponse(
        request,
        "repo.html",
        {
            "user": user,
            "summary": repo_summary(repo),
            "flagged": flagged,
            "clean": clean,
            "unchecked": unchecked,
        },
    )


@app.get("/vulnerabilities")
def vulnerabilities_page(
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    vulns = sorted(
        _user_vulns(session, user), key=lambda v: -severity_rank(v.severity)
    )
    return templates.TemplateResponse(
        request, "vulns.html", {"user": user, "vulns": vulns}
    )


def _create_repo(
    session: Session, user: User, source: str, name: str | None
) -> Repo:
    """Track a repo from either a GitHub URL or a local path."""
    source = source.strip()
    if not source:
        raise HTTPException(422, "source is required")
    if gh := parse_github_url(source):
        owner, repo_name = gh
        repo = Repo(
            user=user,
            name=name or f"{owner}/{repo_name}",
            owner=owner,
            github_url=source,
        )
    else:
        repo = Repo(
            user=user, name=name or Path(source).expanduser().name, local_path=source
        )
    if session.scalar(
        select(Repo).where(Repo.user_id == user.id, Repo.name == repo.name)
    ):
        raise HTTPException(409, f"Repo '{repo.name}' is already tracked")
    session.add(repo)
    session.commit()
    return repo


@app.post("/repos/add")
def add_repo(
    source: str = Form(...),
    name: str = Form(""),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    _create_repo(session, user, source, name.strip() or None)
    return RedirectResponse("/", status_code=303)


@app.post("/repos/{repo_id}/scan")
def trigger_scan(
    repo_id: int,
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    repo = _get_repo(session, user, repo_id)
    try:
        result = scan_repo(session, repo, request.app.state.osv)
    except (FileNotFoundError, GitHubError) as exc:
        raise HTTPException(400, str(exc))
    if request.headers.get("accept", "").startswith("application/json"):
        return result
    return RedirectResponse(f"/repos/{repo_id}", status_code=303)


@app.post("/repos/{repo_id}/delete")
def delete_repo(
    repo_id: int,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    session.delete(_get_repo(session, user, repo_id))
    session.commit()
    return RedirectResponse("/", status_code=303)


# ---------- JSON API ----------

@app.get("/api/repos")
def api_repos(
    user: User = Depends(current_user), session: Session = Depends(get_session)
):
    return [
        {
            "id": s["repo"].id,
            "name": s["repo"].name,
            "local_path": s["repo"].local_path,
            "github_url": s["repo"].github_url,
            "last_scanned_at": s["repo"].last_scanned_at,
            "dependency_count": s["dependency_count"],
            "vulnerable_count": s["vulnerable_count"],
            "highest_severity": s["highest_severity"],
        }
        for s in map(repo_summary, _load_repos(session, user))
    ]


@app.post("/api/repos", status_code=201)
def api_add_repo(
    body: dict,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    source = body.get("source") or body.get("github_url") or body.get("local_path")
    if not source:
        raise HTTPException(422, "source (GitHub URL or local path) is required")
    repo = _create_repo(session, user, source, body.get("name"))
    return {
        "id": repo.id,
        "name": repo.name,
        "local_path": repo.local_path,
        "github_url": repo.github_url,
    }


@app.get("/api/browse")
def api_browse(path: str | None = None, _user: User = Depends(current_user)):
    """List subdirectories for the dashboard's folder picker."""
    target = Path(path).expanduser() if path else Path(config.BROWSE_ROOT)
    try:
        target = target.resolve(strict=True)
    except OSError:
        raise HTTPException(400, f"Not a readable directory: {target}")
    if not target.is_dir():
        raise HTTPException(400, f"Not a directory: {target}")
    try:
        dirs = sorted(
            c.name for c in target.iterdir()
            if c.is_dir() and not c.name.startswith(".")
        )
    except PermissionError:
        raise HTTPException(400, f"Permission denied: {target}")
    return {
        "path": str(target),
        "parent": str(target.parent) if target.parent != target else None,
        "dirs": dirs,
    }


@app.get("/api/repos/{repo_id}/dependencies")
def api_dependencies(
    repo_id: int,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    repo = _get_repo(session, user, repo_id)
    return [
        {
            "name": d.name,
            "version": d.version,
            "ecosystem": d.ecosystem,
            "vulnerabilities": [
                {
                    "osv_id": v.osv_id,
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "summary": v.summary,
                    "risk": explain_risk(v.summary, v.severity),
                    "fixed_version": v.fixed_version,
                }
                for v in d.vulnerabilities
            ],
        }
        for d in repo.dependencies
    ]


@app.get("/api/vulnerabilities")
def api_vulnerabilities(
    user: User = Depends(current_user), session: Session = Depends(get_session)
):
    return sorted(
        (
            {
                "repo": v.dependency.repo.name,
                "package": v.dependency.name,
                "version": v.dependency.version,
                "ecosystem": v.dependency.ecosystem,
                "osv_id": v.osv_id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "summary": v.summary,
                "risk": explain_risk(v.summary, v.severity),
                "affected_range": v.affected_range,
                "fixed_version": v.fixed_version,
            }
            for v in _user_vulns(session, user)
        ),
        key=lambda v: -severity_rank(v["severity"]),
    )
