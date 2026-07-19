from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("provider", "provider_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(20))  # github | google | local
    provider_id: Mapped[str] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(Text)
    # GitHub access token (present after GitHub login or "connect GitHub")
    github_token: Mapped[str | None] = mapped_column(Text)
    github_token_scopes: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    repos: Mapped[list["Repo"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def can_list_github_repos(self) -> bool:
        scopes = (self.github_token_scopes or "").split(",")
        return bool(self.github_token) and "repo" in [s.strip() for s in scopes]


class Repo(Base):
    __tablename__ = "repos"
    __table_args__ = (UniqueConstraint("user_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    owner: Mapped[str | None] = mapped_column(String(255))
    # Exactly one of these is set: scan a local checkout, or fetch via GitHub API
    local_path: Mapped[str | None] = mapped_column(Text)
    github_url: Mapped[str | None] = mapped_column(Text)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    user: Mapped[User] = relationship(back_populates="repos")
    dependencies: Mapped[list["Dependency"]] = relationship(
        back_populates="repo", cascade="all, delete-orphan"
    )
    scans: Mapped[list["ScanHistory"]] = relationship(
        back_populates="repo", cascade="all, delete-orphan"
    )


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("repo_id", "ecosystem", "name", "version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repos.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100))
    ecosystem: Mapped[str] = mapped_column(String(20))  # PyPI | npm
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    repo: Mapped[Repo] = relationship(back_populates="dependencies")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("dependency_id", "osv_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependencies.id", ondelete="CASCADE"), index=True
    )
    osv_id: Mapped[str] = mapped_column(String(100))
    cve_id: Mapped[str | None] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    summary: Mapped[str | None] = mapped_column(Text)
    affected_range: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(String(100))
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    dependency: Mapped[Dependency] = relationship(back_populates="vulnerabilities")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repos.id", ondelete="CASCADE"), index=True
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    dependency_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)

    repo: Mapped[Repo] = relationship(back_populates="scans")
