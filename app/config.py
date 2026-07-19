import os

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql+psycopg://patch:patch@localhost:5432/patch"
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# A given name@version's vulnerability list rarely changes, so cache long.
OSV_CACHE_TTL_SECONDS = int(os.getenv("OSV_CACHE_TTL_SECONDS", str(24 * 3600)))
OSV_API_BASE = os.getenv("OSV_API_BASE", "https://api.osv.dev")
