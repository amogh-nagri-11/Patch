"""Scan a repo's local checkout: find manifests, parse, match against OSV, upsert."""

import logging
import os
from pathlib import Path

from sqlalchemy.orm import Session

from app.github import collect_deps_github
from app.models import Dependency, Repo, ScanHistory, Vulnerability, utcnow
from app.osv import OSVClient
from app.parsers import MANIFEST_PARSERS, SKIP_DIRS, ParsedDep

logger = logging.getLogger(__name__)


def find_manifests(root: Path) -> list[Path]:
    manifests = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        manifests.extend(
            Path(dirpath) / f for f in filenames if f in MANIFEST_PARSERS
        )
    return manifests


def collect_deps(root: Path) -> set[ParsedDep]:
    deps: set[ParsedDep] = set()
    for manifest in find_manifests(root):
        parser = MANIFEST_PARSERS[manifest.name]
        try:
            deps.update(parser(manifest.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Skipping unreadable manifest %s: %s", manifest, exc)
    return deps


def scan_repo(session: Session, repo: Repo, osv: OSVClient) -> dict:
    if repo.github_url:
        deps = collect_deps_github(repo.github_url)
    else:
        root = Path(repo.local_path).expanduser()
        if not root.is_dir():
            raise FileNotFoundError(f"Repo path does not exist: {root}")
        deps = collect_deps(root)
    vuln_map = osv.query(list(deps))
    now = utcnow()

    existing = {
        (d.name, d.ecosystem, d.version): d for d in repo.dependencies
    }
    seen_keys = set()
    for parsed in deps:
        key = (parsed.name, parsed.ecosystem, parsed.version)
        seen_keys.add(key)
        row = existing.get(key)
        if row is None:
            row = Dependency(
                repo=repo,
                name=parsed.name,
                version=parsed.version,
                ecosystem=parsed.ecosystem,
                first_seen_at=now,
            )
            session.add(row)
        row.last_seen_at = now

        # Diff this dependency's vulns against the latest OSV answer: keep
        # unchanged rows (preserves discovered_at), add new, drop withdrawn.
        current = {v.osv_id: v for v in row.vulnerabilities}
        latest = {v.osv_id: v for v in vuln_map.get(parsed, [])}
        for osv_id in current.keys() - latest.keys():
            row.vulnerabilities.remove(current[osv_id])
        for osv_id, rec in latest.items():
            if osv_id in current:
                vuln = current[osv_id]  # advisory may have been updated
                vuln.cve_id = rec.cve_id
                vuln.severity = rec.severity
                vuln.summary = rec.summary
                vuln.affected_range = rec.affected_range
                vuln.fixed_version = rec.fixed_version
            else:
                row.vulnerabilities.append(
                    Vulnerability(
                        osv_id=rec.osv_id,
                        cve_id=rec.cve_id,
                        severity=rec.severity,
                        summary=rec.summary,
                        affected_range=rec.affected_range,
                        fixed_version=rec.fixed_version,
                    )
                )

    # Dependencies no longer in any manifest (removed or version-bumped);
    # removing from the collection triggers the delete-orphan cascade
    for key, row in existing.items():
        if key not in seen_keys:
            repo.dependencies.remove(row)

    vulnerable_count = sum(1 for d in deps if vuln_map.get(d))
    session.add(
        ScanHistory(
            repo=repo,
            scanned_at=now,
            dependency_count=len(deps),
            vulnerable_count=vulnerable_count,
        )
    )
    repo.last_scanned_at = now
    session.commit()

    logger.info(
        "Scanned %s: %d deps, %d vulnerable", repo.name, len(deps), vulnerable_count
    )
    return {
        "repo": repo.name,
        "dependency_count": len(deps),
        "vulnerable_count": vulnerable_count,
    }
