import json
import re

from app.parsers.base import ParsedDep

_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[\w.]+)?$")


def _npm_version(spec: str) -> str | None:
    """Resolve an npm version spec to a concrete version where possible.

    '^1.2.3' and '~1.2.3' are treated as their base version — the true
    installed version needs a lockfile, but the base is the floor the
    project accepts, so it's a useful approximation for CVE matching.
    """
    spec = spec.strip()
    if spec[:1] in ("^", "~"):
        spec = spec[1:]
    return spec if _EXACT_SEMVER_RE.match(spec) else None


def parse_package_json(text: str) -> list[ParsedDep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[ParsedDep] = []
    for section in ("dependencies", "devDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            deps.append(ParsedDep(name, _npm_version(spec), "npm"))
    return deps
