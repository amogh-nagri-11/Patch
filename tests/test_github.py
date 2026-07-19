from app.github import is_manifest_path, parse_github_url


def test_parse_github_url():
    assert parse_github_url("https://github.com/pallets/flask") == ("pallets", "flask")
    assert parse_github_url("http://www.github.com/a/b/") == ("a", "b")
    assert parse_github_url("https://github.com/a/b.git") == ("a", "b")
    assert parse_github_url("https://github.com/a/my-repo.js") == ("a", "my-repo.js")


def test_parse_github_url_rejects_non_repo():
    assert parse_github_url("~/MyProjects/patch") is None
    assert parse_github_url("/usr/local/src/x") is None
    assert parse_github_url("https://gitlab.com/a/b") is None
    assert parse_github_url("https://github.com/onlyowner") is None
    assert parse_github_url("https://github.com/a/b/tree/main") is None


def test_is_manifest_path():
    assert is_manifest_path("requirements.txt")
    assert is_manifest_path("backend/pyproject.toml")
    assert is_manifest_path("web/package.json")
    assert not is_manifest_path("node_modules/lodash/package.json")
    assert not is_manifest_path(".venv/lib/site/requirements.txt")
    assert not is_manifest_path("src/main.py")
