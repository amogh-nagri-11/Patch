import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, selectinload

from app.db import Base, engine, get_session
from app.models import SEVERITY_ORDER, Dependency, Repo, Vulnerability
from app.osv import OSVClient
from app.scanner import scan_repo

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
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)


templates.env.globals["severity_rank"] = severity_rank


def repo_summary(repo: Repo) -> dict:
    vulns = [v for d in repo.dependencies for v in d.vulnerabilities]
    highest = max((v.severity for v in vulns), key=severity_rank, default=None)
    return {
        "repo": repo,
        "dependency_count": len(repo.dependencies),
        "vulnerable_count": sum(1 for d in repo.dependencies if d.vulnerabilities),
        "highest_severity": highest,
    }


def _load_repos(session: Session) -> list[Repo]:
    return list(
        session.scalars(
            select(Repo)
            .options(selectinload(Repo.dependencies).selectinload(Dependency.vulnerabilities))
            .order_by(Repo.name)
        )
    )


def _get_repo(session: Session, repo_id: int) -> Repo:
    repo = session.get(Repo, repo_id)
    if repo is None:
        raise HTTPException(404, "Repo not found")
    return repo


# ---------- Dashboard pages ----------

@app.get("/")
def index(request: Request, session: Session = Depends(get_session)):
    summaries = [repo_summary(r) for r in _load_repos(session)]
    return templates.TemplateResponse(
        request, "index.html", {"summaries": summaries}
    )


@app.get("/repos/{repo_id}")
def repo_detail(repo_id: int, request: Request, session: Session = Depends(get_session)):
    repo = _get_repo(session, repo_id)
    deps = sorted(
        repo.dependencies,
        key=lambda d: (
            -max((severity_rank(v.severity) for v in d.vulnerabilities), default=-1),
            d.name,
        ),
    )
    for d in deps:
        d.vulnerabilities.sort(key=lambda v: -severity_rank(v.severity))
    return templates.TemplateResponse(
        request, "repo.html", {"summary": repo_summary(repo), "deps": deps}
    )


@app.get("/vulnerabilities")
def vulnerabilities_page(request: Request, session: Session = Depends(get_session)):
    vulns = session.scalars(
        select(Vulnerability).options(
            selectinload(Vulnerability.dependency).selectinload(Dependency.repo)
        )
    ).all()
    vulns = sorted(vulns, key=lambda v: -severity_rank(v.severity))
    return templates.TemplateResponse(request, "vulns.html", {"vulns": vulns})


@app.post("/repos/add")
def add_repo(
    name: str = Form(...),
    local_path: str = Form(...),
    session: Session = Depends(get_session),
):
    if session.scalar(select(Repo).where(Repo.name == name)):
        raise HTTPException(409, f"Repo '{name}' is already tracked")
    session.add(Repo(name=name, local_path=local_path))
    session.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/repos/{repo_id}/scan")
def trigger_scan(
    repo_id: int, request: Request, session: Session = Depends(get_session)
):
    repo = _get_repo(session, repo_id)
    try:
        result = scan_repo(session, repo, request.app.state.osv)
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    if request.headers.get("accept", "").startswith("application/json"):
        return result
    return RedirectResponse(f"/repos/{repo_id}", status_code=303)


@app.post("/repos/{repo_id}/delete")
def delete_repo(repo_id: int, session: Session = Depends(get_session)):
    session.delete(_get_repo(session, repo_id))
    session.commit()
    return RedirectResponse("/", status_code=303)


# ---------- JSON API ----------

@app.get("/api/repos")
def api_repos(session: Session = Depends(get_session)):
    return [
        {
            "id": s["repo"].id,
            "name": s["repo"].name,
            "local_path": s["repo"].local_path,
            "last_scanned_at": s["repo"].last_scanned_at,
            "dependency_count": s["dependency_count"],
            "vulnerable_count": s["vulnerable_count"],
            "highest_severity": s["highest_severity"],
        }
        for s in map(repo_summary, _load_repos(session))
    ]


@app.post("/api/repos", status_code=201)
def api_add_repo(body: dict, session: Session = Depends(get_session)):
    name, local_path = body.get("name"), body.get("local_path")
    if not name or not local_path:
        raise HTTPException(422, "name and local_path are required")
    if session.scalar(select(Repo).where(Repo.name == name)):
        raise HTTPException(409, f"Repo '{name}' is already tracked")
    repo = Repo(name=name, local_path=local_path)
    session.add(repo)
    session.commit()
    return {"id": repo.id, "name": repo.name, "local_path": repo.local_path}


@app.get("/api/repos/{repo_id}/dependencies")
def api_dependencies(repo_id: int, session: Session = Depends(get_session)):
    repo = _get_repo(session, repo_id)
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
                    "fixed_version": v.fixed_version,
                }
                for v in d.vulnerabilities
            ],
        }
        for d in repo.dependencies
    ]


@app.get("/api/vulnerabilities")
def api_vulnerabilities(session: Session = Depends(get_session)):
    vulns = session.scalars(
        select(Vulnerability).options(
            selectinload(Vulnerability.dependency).selectinload(Dependency.repo)
        )
    ).all()
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
                "affected_range": v.affected_range,
                "fixed_version": v.fixed_version,
            }
            for v in vulns
        ),
        key=lambda v: -severity_rank(v["severity"]),
    )
