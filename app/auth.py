"""Multi-user auth: GitHub + Google OAuth login, plus GitHub repo import.

Sessions are signed cookies (SessionMiddleware) holding the user id.
If no OAuth provider is configured, the app runs in single-user dev mode:
every request is implicitly the "local" user and no login is required.

GitHub scopes are tiered: login asks only for read:user (public profile);
the broader `repo` scope is requested separately when the user chooses to
import repos, so signing in never demands repository access.
"""

import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.db import get_session
from app.models import Repo, User
from app.templating import templates

router = APIRouter()


class AuthRequired(Exception):
    """Raised when a route needs a logged-in user; handled in main.py."""


def github_enabled() -> bool:
    return bool(config.GITHUB_CLIENT_ID and config.GITHUB_CLIENT_SECRET)


def google_enabled() -> bool:
    return bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET)


def auth_enabled() -> bool:
    return github_enabled() or google_enabled()


def _local_user(session: Session) -> User:
    user = session.scalar(select(User).where(User.provider == "local"))
    if user is None:
        user = User(provider="local", provider_id="local", username="local")
        session.add(user)
        session.commit()
    return user


def current_user(
    request: Request, session: Session = Depends(get_session)
) -> User:
    user_id = request.session.get("user_id")
    if user_id is not None:
        user = session.get(User, user_id)
        if user is not None:
            return user
    if not auth_enabled():
        user = _local_user(session)
        request.session["user_id"] = user.id
        return user
    raise AuthRequired()


def _new_state(request: Request) -> str:
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    return state


def _check_state(request: Request, state: str) -> None:
    if not state or state != request.session.pop("oauth_state", None):
        raise HTTPException(400, "OAuth state mismatch — try logging in again")


def _login_user(request: Request, user: User) -> None:
    request.session["user_id"] = user.id


def _upsert_oauth_user(
    session: Session, provider: str, provider_id: str, **fields
) -> User:
    user = session.scalar(
        select(User).where(
            User.provider == provider, User.provider_id == provider_id
        )
    )
    if user is None:
        user = User(provider=provider, provider_id=provider_id, **fields)
        session.add(user)
    else:
        for key, value in fields.items():
            setattr(user, key, value)
    session.commit()
    return user


# ---------- Login / logout ----------

@router.get("/login")
def login_page(request: Request, session: Session = Depends(get_session)):
    if not auth_enabled() or request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "user": None,
            "github_enabled": github_enabled(),
            "google_enabled": google_enabled(),
        },
    )


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- GitHub OAuth ----------

@router.get("/auth/github/login")
def github_login(request: Request, connect: int = 0):
    if not github_enabled():
        raise HTTPException(404, "GitHub OAuth is not configured")
    # connect=1: an existing session wants repo-listing permission
    request.session["oauth_intent"] = "connect" if connect else "login"
    params = {
        "client_id": config.GITHUB_CLIENT_ID,
        "redirect_uri": f"{config.BASE_URL}/auth/github/callback",
        "scope": "repo read:user" if connect else "read:user",
        "state": _new_state(request),
    }
    return RedirectResponse(
        "https://github.com/login/oauth/authorize?" + urlencode(params)
    )


@router.get("/auth/github/callback")
def github_callback(
    request: Request,
    code: str = "",
    state: str = "",
    session: Session = Depends(get_session),
):
    _check_state(request, state)
    if not code:
        raise HTTPException(400, "GitHub login was cancelled")

    token_resp = httpx.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": config.GITHUB_CLIENT_ID,
            "client_secret": config.GITHUB_CLIENT_SECRET,
            "code": code,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    ).json()
    token = token_resp.get("access_token")
    if not token:
        raise HTTPException(400, f"GitHub token exchange failed: {token_resp}")
    scopes = token_resp.get("scope", "")

    gh_user = httpx.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    ).json()

    intent = request.session.pop("oauth_intent", "login")
    existing_id = request.session.get("user_id")
    if intent == "connect" and existing_id is not None:
        # Attach GitHub access to whoever is already logged in (e.g. a
        # Google-login user connecting GitHub for repo import)
        user = session.get(User, existing_id)
        if user is None:
            raise AuthRequired()
    else:
        user = _upsert_oauth_user(
            session,
            "github",
            str(gh_user["id"]),
            username=gh_user["login"],
            email=gh_user.get("email"),
            avatar_url=gh_user.get("avatar_url"),
        )
    user.github_token = token
    user.github_token_scopes = scopes
    session.commit()
    _login_user(request, user)
    return RedirectResponse(
        "/import" if intent == "connect" else "/", status_code=303
    )


# ---------- Google OAuth (OpenID Connect) ----------

@router.get("/auth/google/login")
def google_login(request: Request):
    if not google_enabled():
        raise HTTPException(404, "Google OAuth is not configured")
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": f"{config.BASE_URL}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": _new_state(request),
    }
    return RedirectResponse(
        "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    )


@router.get("/auth/google/callback")
def google_callback(
    request: Request,
    code: str = "",
    state: str = "",
    session: Session = Depends(get_session),
):
    _check_state(request, state)
    if not code:
        raise HTTPException(400, "Google login was cancelled")

    token_resp = httpx.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{config.BASE_URL}/auth/google/callback",
            "grant_type": "authorization_code",
        },
        timeout=30,
    ).json()
    token = token_resp.get("access_token")
    if not token:
        raise HTTPException(400, "Google token exchange failed")

    info = httpx.get(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    ).json()
    email = info.get("email")
    user = _upsert_oauth_user(
        session,
        "google",
        str(info["sub"]),
        username=info.get("name") or (email or "google-user").split("@")[0],
        email=email,
        avatar_url=info.get("picture"),
    )
    _login_user(request, user)
    return RedirectResponse("/", status_code=303)


# ---------- GitHub repo import ----------

@router.get("/import")
def import_page(
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    if not user.can_list_github_repos:
        return templates.TemplateResponse(
            request,
            "import.html",
            {
                "user": user,
                "connect_needed": True,
                "github_enabled": github_enabled(),
            },
        )
    resp = httpx.get(
        "https://api.github.com/user/repos",
        params={"per_page": 100, "sort": "updated"},
        headers={"Authorization": f"Bearer {user.github_token}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise HTTPException(502, f"GitHub API error {resp.status_code}")
    tracked_urls = {r.github_url for r in user.repos if r.github_url}
    gh_repos = [
        {
            "full_name": r["full_name"],
            "html_url": r["html_url"],
            "private": r["private"],
            "tracked": r["html_url"] in tracked_urls,
        }
        for r in resp.json()
    ]
    return templates.TemplateResponse(
        request,
        "import.html",
        {"user": user, "connect_needed": False, "gh_repos": gh_repos},
    )


@router.post("/import")
def import_repos(
    request: Request,
    repos: list[str] = Form(default=[]),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    existing_names = {r.name for r in user.repos}
    for full_name in repos:
        if "/" not in full_name or full_name in existing_names:
            continue
        owner = full_name.split("/")[0]
        session.add(
            Repo(
                user=user,
                name=full_name,
                owner=owner,
                github_url=f"https://github.com/{full_name}",
            )
        )
    session.commit()
    return RedirectResponse("/", status_code=303)
