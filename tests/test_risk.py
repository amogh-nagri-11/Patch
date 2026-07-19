from app.risk import explain_risk


def test_classifies_known_vulnerability_types():
    cases = {
        "Remote Code Execution in yaml loader": "run their own code",
        "lodash Prototype Pollution": "object internals",
        "Inefficient Regular Expression Complexity": "slow regex",
        "SQL Injection via search parameter": "your database",
        "Reflected XSS in error page": "inject scripts",
        "Path traversal in static file handler": "outside the folders",
        "SSRF via redirect handling": "internal systems",
        "Denial of service via crafted header": "unresponsive",
        "Session token information disclosure": "exposed",
    }
    for summary, expected_fragment in cases.items():
        assert expected_fragment in explain_risk(summary, "HIGH"), summary


def test_urgency_scales_with_severity():
    assert "immediately" in explain_risk("SQL injection", "CRITICAL")
    assert "as soon as possible" in explain_risk("SQL injection", "HIGH")
    assert "next touch" in explain_risk("SQL injection", "MEDIUM")
    assert "opportunistically" in explain_risk("SQL injection", "LOW")


def test_generic_fallback_when_unclassifiable():
    text = explain_risk("Improper widget frobnication", "HIGH")
    assert "serious flaw" in text
    text = explain_risk(None, "UNKNOWN")
    assert "advisory" in text
