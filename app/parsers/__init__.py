from app.parsers.base import ParsedDep
from app.parsers.node_parser import parse_package_json
from app.parsers.python_parser import parse_pyproject, parse_requirements

# Maps manifest filename -> parser(text) -> list[ParsedDep]
MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
}

# Directories whose manifests belong to other packages, not this repo
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env",
    "dist", "build", "__pycache__", ".tox", "site-packages",
}

__all__ = ["ParsedDep", "MANIFEST_PARSERS", "SKIP_DIRS", "parse_requirements", "parse_pyproject", "parse_package_json"]
