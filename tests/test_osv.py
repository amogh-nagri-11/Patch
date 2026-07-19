from app.osv import summarize_vuln
from app.parsers import ParsedDep

VULN_FIXTURE = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2023-12345"],
    "summary": "Prototype pollution in example",
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "example"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "other"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}]}],
        },
    ],
}


def test_summarize_vuln():
    dep = ParsedDep("example", "4.17.0", "npm")
    record = summarize_vuln(VULN_FIXTURE, dep)
    assert record.osv_id == "GHSA-xxxx-yyyy-zzzz"
    assert record.cve_id == "CVE-2023-12345"
    assert record.severity == "MEDIUM"  # MODERATE normalized
    assert record.fixed_version == "4.17.21"
    assert record.affected_range == ">=0, <4.17.21"  # only the npm/example entry


def test_summarize_vuln_no_severity_or_alias():
    vuln = {"id": "PYSEC-2024-1", "affected": [], "details": "d" * 500}
    record = summarize_vuln(vuln, ParsedDep("x", "1.0", "PyPI"))
    assert record.cve_id is None
    assert record.severity == "UNKNOWN"
    assert record.fixed_version is None
    assert len(record.summary) == 300  # details truncated
