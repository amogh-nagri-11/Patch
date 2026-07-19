import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedDep:
    name: str
    version: str | None  # None when the manifest doesn't pin an exact version
    ecosystem: str  # "PyPI" | "npm" (OSV.dev ecosystem names)


def canonical_pypi_name(name: str) -> str:
    # PEP 503 normalization: Flask_SQLAlchemy -> flask-sqlalchemy
    return re.sub(r"[-_.]+", "-", name).lower()
