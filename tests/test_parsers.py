from app.parsers import ParsedDep, parse_package_json, parse_pyproject, parse_requirements


def test_requirements_pinned_and_unpinned():
    text = """\
# comment
requests==2.31.0
Flask_SQLAlchemy==3.0.5  # inline comment
uvicorn[standard]==0.29.0
numpy>=1.24
plainname
-r other.txt
-e .
git+https://github.com/x/y.git
django==4.2.* ; python_version >= "3.10"
"""
    deps = {d.name: d for d in parse_requirements(text)}
    assert deps["requests"].version == "2.31.0"
    assert deps["flask-sqlalchemy"].version == "3.0.5"  # PEP 503 normalized
    assert deps["uvicorn"].version == "0.29.0"  # extras stripped
    assert deps["numpy"].version is None  # range, not a pin
    assert deps["plainname"].version is None
    assert deps["django"].version is None  # wildcard pin isn't exact
    assert "other.txt" not in deps and len(deps) == 6
    assert all(d.ecosystem == "PyPI" for d in deps.values())


def test_pyproject_pep621_and_poetry():
    text = """\
[project]
name = "demo"
dependencies = ["httpx==0.27.0", "pydantic>=2"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
click = { version = "8.1.7" }
flask = "^2.0"
"""
    deps = {d.name: d.version for d in parse_pyproject(text)}
    assert deps["httpx"] == "0.27.0"
    assert deps["pydantic"] is None
    assert deps["requests"] == "2.31.0"
    assert deps["click"] == "8.1.7"
    assert deps["flask"] is None  # caret range, not exact
    assert "python" not in deps


def test_pyproject_invalid_toml():
    assert parse_pyproject("not [ valid toml") == []


def test_package_json():
    text = """{
      "dependencies": {
        "express": "4.18.2",
        "lodash": "^4.17.21",
        "left-pad": "~1.3.0",
        "weird": "*",
        "local": "file:../local",
        "ranged": ">=1.0.0 <2.0.0"
      },
      "devDependencies": { "jest": "29.7.0" }
    }"""
    deps = {d.name: d.version for d in parse_package_json(text)}
    assert deps["express"] == "4.18.2"
    assert deps["lodash"] == "4.17.21"  # caret stripped to base version
    assert deps["left-pad"] == "1.3.0"
    assert deps["weird"] is None
    assert deps["local"] is None
    assert deps["ranged"] is None
    assert deps["jest"] == "29.7.0"


def test_package_json_invalid():
    assert parse_package_json("{oops") == []


def test_parsed_dep_hashable():
    assert len({ParsedDep("a", "1", "npm"), ParsedDep("a", "1", "npm")}) == 1
