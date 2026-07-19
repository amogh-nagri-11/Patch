"""Plain-English risk explanations derived from advisory text + severity.

OSV summaries are written for security folks ("Prototype pollution in lodash").
This maps the vulnerability class to what it actually lets an attacker do.
"""

# Checked in order — first keyword hit wins, so more specific classes go first.
_PATTERNS: list[tuple[tuple[str, ...], str]] = [
    (
        ("remote code execution", "arbitrary code", "code execution",
         "command injection", "arbitrary command", "deserialization of untrusted"),
        "An attacker could run their own code on the machine running your app — "
        "the most serious kind of flaw.",
    ),
    (
        ("sql injection",),
        "Crafted input could read or modify your database directly.",
    ),
    (
        ("cross-site scripting", "xss"),
        "An attacker could inject scripts into pages your users see, hijacking "
        "their sessions or actions.",
    ),
    (
        ("path traversal", "directory traversal", "arbitrary file"),
        "Crafted requests could read or write files outside the folders your "
        "app intends to expose.",
    ),
    (
        ("server-side request forgery", "ssrf"),
        "An attacker could make your server send requests on their behalf, "
        "often to reach internal systems.",
    ),
    (
        ("prototype pollution",),
        "Crafted input can tamper with JavaScript object internals, which can "
        "corrupt app logic and sometimes escalate to running attacker code.",
    ),
    (
        ("redos", "regular expression denial of service", "catastrophic backtracking",
         "inefficient regular expression"),
        "A specially crafted string can make the app hang or burn CPU "
        "(denial of service via slow regex).",
    ),
    (
        ("denial of service", "dos", "crash", "infinite loop", "resource exhaustion",
         "memory exhaustion"),
        "An attacker could crash the app or make it unresponsive.",
    ),
    (
        ("cross-site request forgery", "csrf"),
        "A malicious site could trick logged-in users' browsers into performing "
        "actions they never intended.",
    ),
    (
        ("open redirect",),
        "Links through your app could silently redirect users to attacker "
        "sites — useful for phishing.",
    ),
    (
        ("authentication bypass", "improper authentication", "access control",
         "authorization bypass", "privilege escalation"),
        "An attacker could get past login or permission checks and act with "
        "access they shouldn't have.",
    ),
    (
        ("request smuggling", "header injection", "crlf injection"),
        "Crafted requests could be misinterpreted between servers, letting "
        "attackers slip past security controls.",
    ),
    (
        ("information disclosure", "information exposure", "sensitive information",
         "credentials leak", "leak", "cleartext"),
        "Sensitive data (tokens, credentials, internal details) could be "
        "exposed to parties who shouldn't see it.",
    ),
    (
        ("timing attack", "timing oracle", "observable discrepancy"),
        "Response-time differences could let an attacker gradually guess "
        "secrets like tokens or passwords.",
    ),
]

_GENERIC = {
    "CRITICAL": "A severe flaw in this package version that is likely "
    "exploitable in real deployments.",
    "HIGH": "A serious flaw in this package version that attackers could "
    "plausibly exploit.",
    "MEDIUM": "A moderate flaw — exploitable only in certain configurations "
    "or with limited impact.",
    "LOW": "A minor flaw with limited practical impact.",
    "UNKNOWN": "This package version has a published advisory; impact details "
    "are limited.",
}

_URGENCY = {
    "CRITICAL": "Update immediately.",
    "HIGH": "Update as soon as possible.",
    "MEDIUM": "Update when you next touch this project.",
    "LOW": "Fix opportunistically.",
    "UNKNOWN": "Review the advisory to judge urgency.",
}


def explain_risk(summary: str | None, severity: str) -> str:
    text = (summary or "").lower()
    explanation = next(
        (msg for keywords, msg in _PATTERNS if any(k in text for k in keywords)),
        _GENERIC.get(severity, _GENERIC["UNKNOWN"]),
    )
    return f"{explanation} {_URGENCY.get(severity, _URGENCY['UNKNOWN'])}"
