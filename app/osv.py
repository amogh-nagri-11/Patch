"""OSV.dev client: batch vulnerability queries with a Redis cache.

Cache layout:
  osv:q:{ecosystem}:{name}@{version} -> JSON list of OSV vuln IDs
  osv:vuln:{osv_id}                  -> JSON of the summarized vuln record
"""

import json
import logging
from dataclasses import asdict, dataclass

import httpx
import redis

from app import config
from app.parsers import ParsedDep

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500  # OSV querybatch caps at 1000 queries per call


@dataclass
class VulnRecord:
    osv_id: str
    cve_id: str | None
    severity: str
    summary: str | None
    affected_range: str | None
    fixed_version: str | None


_SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}
_KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _extract_severity(vuln: dict) -> str:
    raw = (vuln.get("database_specific") or {}).get("severity", "")
    sev = _SEVERITY_ALIASES.get(raw.upper(), raw.upper())
    return sev if sev in _KNOWN_SEVERITIES else "UNKNOWN"


def _matching_affected(vuln: dict, dep: ParsedDep) -> list[dict]:
    return [
        aff
        for aff in vuln.get("affected", [])
        if (pkg := aff.get("package", {})).get("ecosystem") == dep.ecosystem
        and pkg.get("name", "").lower() == dep.name.lower()
    ]


def _extract_ranges(vuln: dict, dep: ParsedDep) -> tuple[str | None, str | None]:
    """Return (human-readable affected range, last fixed version) for this package."""
    parts: list[str] = []
    fixed_version = None
    for aff in _matching_affected(vuln, dep):
        for rng in aff.get("ranges", []):
            introduced = fixed = None
            for event in rng.get("events", []):
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed)
            if fixed:
                fixed_version = fixed
            if introduced is not None or fixed is not None:
                lower = ">=" + (introduced or "0")
                parts.append(f"{lower}, <{fixed}" if fixed else lower)
    return ("; ".join(parts) or None, fixed_version)


def summarize_vuln(vuln: dict, dep: ParsedDep) -> VulnRecord:
    cve_id = next(
        (a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None
    )
    affected_range, fixed_version = _extract_ranges(vuln, dep)
    summary = vuln.get("summary") or (vuln.get("details") or "")[:300] or None
    return VulnRecord(
        osv_id=vuln["id"],
        cve_id=cve_id,
        severity=_extract_severity(vuln),
        summary=summary,
        affected_range=affected_range,
        fixed_version=fixed_version,
    )


class OSVClient:
    def __init__(self, redis_url: str = config.REDIS_URL):
        self._http = httpx.Client(base_url=config.OSV_API_BASE, timeout=30)
        try:
            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
        except redis.RedisError:
            logger.warning("Redis unavailable at %s — running without cache", redis_url)
            self._redis = None

    def _cache_get(self, key: str):
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(key)
            return json.loads(raw) if raw is not None else None
        except redis.RedisError:
            return None

    def _cache_set(self, key: str, value) -> None:
        if self._redis is None:
            return
        try:
            self._redis.set(key, json.dumps(value), ex=config.OSV_CACHE_TTL_SECONDS)
        except redis.RedisError:
            pass

    @staticmethod
    def _query_key(dep: ParsedDep) -> str:
        return f"osv:q:{dep.ecosystem}:{dep.name}@{dep.version}"

    def query(self, deps: list[ParsedDep]) -> dict[ParsedDep, list[VulnRecord]]:
        """Map each dep (with a concrete version) to its vulnerabilities."""
        deps = [d for d in deps if d.version]
        results: dict[ParsedDep, list[str]] = {}

        uncached = []
        for dep in deps:
            ids = self._cache_get(self._query_key(dep))
            if ids is not None:
                results[dep] = ids
            else:
                uncached.append(dep)

        for start in range(0, len(uncached), _BATCH_SIZE):
            batch = uncached[start : start + _BATCH_SIZE]
            resp = self._http.post(
                "/v1/querybatch",
                json={
                    "queries": [
                        {
                            "package": {"name": d.name, "ecosystem": d.ecosystem},
                            "version": d.version,
                        }
                        for d in batch
                    ]
                },
            )
            resp.raise_for_status()
            for dep, result in zip(batch, resp.json().get("results", [])):
                ids = [v["id"] for v in (result or {}).get("vulns", [])]
                results[dep] = ids
                self._cache_set(self._query_key(dep), ids)

        return {
            dep: [self._get_vuln(osv_id, dep) for osv_id in ids]
            for dep, ids in results.items()
        }

    def _get_vuln(self, osv_id: str, dep: ParsedDep) -> VulnRecord:
        cached = self._cache_get(f"osv:vuln:{osv_id}:{dep.ecosystem}:{dep.name}")
        if cached is not None:
            return VulnRecord(**cached)
        resp = self._http.get(f"/v1/vulns/{osv_id}")
        resp.raise_for_status()
        record = summarize_vuln(resp.json(), dep)
        self._cache_set(
            f"osv:vuln:{osv_id}:{dep.ecosystem}:{dep.name}", asdict(record)
        )
        return record
