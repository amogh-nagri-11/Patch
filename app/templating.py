from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.models import SEVERITY_ORDER
from app.risk import explain_risk

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)


templates.env.globals["severity_rank"] = severity_rank
templates.env.globals["explain_risk"] = explain_risk
