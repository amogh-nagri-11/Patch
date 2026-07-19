from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Repo, ScanHistory, Vulnerability
from app.osv import VulnRecord
from app.scanner import scan_repo


class FakeOSV:
    """Flags flask==2.0.0 with one vulnerability; everything else clean."""

    def query(self, deps):
        return {
            d: [
                VulnRecord(
                    osv_id="GHSA-test-1",
                    cve_id="CVE-2023-30861",
                    severity="HIGH",
                    summary="cookie disclosure",
                    affected_range=">=0, <2.2.5",
                    fixed_version="2.2.5",
                )
            ]
            for d in deps
            if d.name == "flask" and d.version == "2.0.0"
        }


def make_session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_rescan_with_existing_vulns_does_not_crash(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\nhttpx==0.27.0\n")
    session = make_session()
    repo = Repo(name="t", local_path=str(tmp_path))
    session.add(repo)
    session.commit()

    result = scan_repo(session, repo, FakeOSV())
    assert result == {"repo": "t", "dependency_count": 2, "vulnerable_count": 1}
    first = session.scalars(select(Vulnerability)).one()
    first_discovered = first.discovered_at

    # Regression: this used to raise IntegrityError (insert-before-delete on
    # the (dependency_id, osv_id) unique constraint)
    scan_repo(session, repo, FakeOSV())
    vuln = session.scalars(select(Vulnerability)).one()
    assert vuln.discovered_at == first_discovered  # unchanged vuln row kept
    assert len(session.scalars(select(ScanHistory)).all()) == 2


def test_scan_reflects_dependency_fix(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==2.0.0\n")
    session = make_session()
    repo = Repo(name="t", local_path=str(tmp_path))
    session.add(repo)
    session.commit()

    scan_repo(session, repo, FakeOSV())
    assert session.scalars(select(Vulnerability)).one()

    manifest.write_text("flask==2.2.5\n")  # user upgrades to the fixed version
    result = scan_repo(session, repo, FakeOSV())
    assert result["vulnerable_count"] == 0
    assert session.scalars(select(Vulnerability)).all() == []
    versions = {d.version for d in repo.dependencies}
    assert versions == {"2.2.5"}  # old 2.0.0 row pruned
