from app.parsers.base import ParsedDep
from app.parsers.node_parser import parse_package_json
from app.parsers.python_parser import parse_pyproject, parse_requirements

# Maps manifest filename -> parser(text) -> list[ParsedDep]
MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
}

__all__ = ["ParsedDep", "MANIFEST_PARSERS", "parse_requirements", "parse_pyproject", "parse_package_json"]
