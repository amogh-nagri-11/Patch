import os

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql+psycopg://patch:patch@localhost:5432/patch"
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# A given name@version's vulnerability list rarely changes, so cache long.
OSV_CACHE_TTL_SECONDS = int(os.getenv("OSV_CACHE_TTL_SECONDS", str(24 * 3600)))
OSV_API_BASE = os.getenv("OSV_API_BASE", "https://api.osv.dev")

# Optional PAT: raises GitHub rate limits and allows private repos
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Where the dashboard's folder browser starts (/repos inside Docker)
BROWSE_ROOT = os.getenv(
    "BROWSE_ROOT", "/repos" if os.path.isdir("/repos") else os.path.expanduser("~")
)

# --- Auth ---
# Signs the session cookie; MUST be set to a random value in production
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret")
# Public URL of this instance; OAuth callbacks are built from it
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")

# OAuth apps. If neither provider is configured, Patch runs in single-user
# dev mode: no login page, everything belongs to an implicit "local" user.
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
