"""Entra ID (Azure AD) OIDC login, via MSAL's authorization-code flow.

This is a normal browser redirect login (unlike graph_client.py's device-
code flow, which exists because a CLI has no browser of its own) - the
web app always has a real browser in front of the user, so the standard
web sign-in flow is the right fit here.
"""

import secrets

import msal
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import config

router = APIRouter()

_STATE_COOKIE = "oauth_state"


def _msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=config.ENTRA_CLIENT_ID,
        client_credential=config.ENTRA_CLIENT_SECRET,
        authority=config.ENTRA_AUTHORITY,
    )


def current_user(request: Request) -> dict | None:
    return request.session.get("user")


def require_login(request: Request) -> dict:
    """FastAPI dependency for PAGE routes: redirects to /login if not
    signed in. Dev bypass is handled entirely here so every other route
    just depends on this one function regardless of which mode is active."""
    if config.DEV_BYPASS_AUTH:
        return {"oid": "dev-user", "name": "Dev User", "email": "dev@localhost"}
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


def require_login_api(request: Request) -> dict:
    """FastAPI dependency for JSON/API routes: a 401 is the right response
    for a fetch()/EventSource call, not a redirect the browser would
    follow into an HTML login page the caller isn't expecting."""
    if config.DEV_BYPASS_AUTH:
        return {"oid": "dev-user", "name": "Dev User", "email": "dev@localhost"}
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return user


@router.get("/auth/start")
def auth_start(request: Request):
    """Kicks off the actual Microsoft sign-in redirect (or the dev bypass).
    Separate from GET /login, which is just the landing page with the
    'Sign in with Microsoft' button - avoids both routes fighting over
    the same path."""
    if config.DEV_BYPASS_AUTH:
        request.session["user"] = {"oid": "dev-user", "name": "Dev User", "email": "dev@localhost"}
        return RedirectResponse("/")

    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    auth_url = _msal_app().get_authorization_request_url(
        scopes=config.ENTRA_SCOPES,
        state=state,
        redirect_uri=config.ENTRA_REDIRECT_URI,
    )
    return RedirectResponse(auth_url)


@router.get("/auth/callback")
def auth_callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        raise HTTPException(status_code=400, detail=f"Sign-in failed: {error} - {error_description}")

    expected_state = request.session.pop("oauth_state", None)
    if not expected_state or state != expected_state:
        raise HTTPException(status_code=400, detail="Sign-in state mismatch - please try logging in again.")

    result = _msal_app().acquire_token_by_authorization_code(
        code,
        scopes=config.ENTRA_SCOPES,
        redirect_uri=config.ENTRA_REDIRECT_URI,
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=f"Sign-in failed: {result.get('error_description', result['error'])}")

    claims = result.get("id_token_claims", {})
    request.session["user"] = {
        "oid": claims.get("oid", claims.get("sub", "")),
        "name": claims.get("name", ""),
        "email": claims.get("preferred_username", claims.get("email", "")),
    }
    return RedirectResponse("/")


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")
