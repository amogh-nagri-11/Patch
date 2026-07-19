import re
import tomllib

from app.parsers.base import ParsedDep, canonical_pypi_name

# PEP 508-ish: name, optional extras, then the version spec / markers
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _exact_version(spec: str) -> str | None:
    """Return the pinned version from a spec like '==1.2.3', else None."""
    spec = spec.split(";")[0].strip()  # drop environment markers
    if not spec.startswith("=="):
        return None
    version = spec[2:].split(",")[0].strip()
    if not version or version.endswith(".*"):
        return None
    return version


def _parse_req_line(line: str) -> ParsedDep | None:
    line = line.split("#")[0].strip()
    if not line:
        return None
    # Skip pip options (-r, -e, --index-url, ...) and direct URL/path requirements
    if line.startswith("-") or "://" in line or line.startswith((".", "/")):
        return None
    match = _REQ_RE.match(line)
    if not match:
        return None
    name, _, spec = match.groups()
    return ParsedDep(canonical_pypi_name(name), _exact_version(spec), "PyPI")


def parse_requirements(text: str) -> list[ParsedDep]:
    deps = []
    for raw_line in text.splitlines():
        if raw_line.endswith("\\"):
            raw_line = raw_line[:-1]
        dep = _parse_req_line(raw_line)
        if dep:
            deps.append(dep)
    return deps


_POETRY_EXACT_RE = re.compile(r"^\d[\w.+!-]*$")


def _poetry_version(value) -> str | None:
    if isinstance(value, dict):
        value = value.get("version", "")
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith("=="):
        value = value[2:]
    return value if _POETRY_EXACT_RE.match(value) else None


def parse_pyproject(text: str) -> list[ParsedDep]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps: list[ParsedDep] = []

    # PEP 621: [project] dependencies = ["requests==2.31.0", ...]
    for req in data.get("project", {}).get("dependencies", []):
        if isinstance(req, str):
            dep = _parse_req_line(req)
            if dep:
                deps.append(dep)

    # Poetry: [tool.poetry.dependencies] requests = "2.31.0" / { version = "..." }
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, value in poetry_deps.items():
        if name.lower() == "python":
            continue
        deps.append(
            ParsedDep(canonical_pypi_name(name), _poetry_version(value), "PyPI")
        )

    return deps
