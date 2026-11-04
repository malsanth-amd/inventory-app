"""Microsoft Graph API client with OAuth2 device code authentication.

Vendored from the user's own m365-sharepoint Claude Code skill
(~/.claude/skills/m365-sharepoint/scripts/graph_client.py) so FlashTools
doesn't depend on that skill being installed on a recipient's machine -
this file is self-contained, pure stdlib (urllib/ssl/json/base64), no new
pip dependency. Used by refresh_recipe_bkc_page_cli.py to download FPGA
firmware directly from SharePoint instead of a Confluence attachment
(avoids the CASB-blocked raw-HTTP path AND the Playwright/Chromium
browser-automation path entirely for that component).

Token persistence/refresh is automatic: complete_auth() and the internal
_refresh() both call _save_token(), so after the one-time device-code
login, every later run silently refreshes the access token from the saved
refresh_token with no user interaction - no need to repeat login unless
the refresh_token itself eventually expires (Microsoft's typical inactivity
window is long, ~90 days).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

_SSL_CONTEXT: ssl.SSLContext | None = None


def _ssl_context() -> ssl.SSLContext:
    """Build an SSL context that honors common CA-bundle env overrides.

    Python's stdlib defaults check ``/etc/ssl/cert.pem`` and ``/etc/ssl/certs``,
    which are empty on RHEL 8/9/10. Without an override Python sees zero
    trusted CAs and TLS handshakes to ``login.microsoftonline.com`` fail with
    ``CERTIFICATE_VERIFY_FAILED`` ~1 hour after auth (when the silent token
    refresh runs). Initial auth via browser succeeds because the browser uses
    its own trust store, not Python's.
    """
    global _SSL_CONTEXT
    if _SSL_CONTEXT is not None:
        return _SSL_CONTEXT
    cafile = (
        os.environ.get("SSL_CERT_FILE")
        or os.environ.get("REQUESTS_CA_BUNDLE")
        or os.environ.get("CURL_CA_BUNDLE")
    )
    if not cafile:
        for cand in (
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        ):
            if os.path.isfile(cand):
                cafile = cand
                break
    _SSL_CONTEXT = (
        ssl.create_default_context(cafile=cafile)
        if cafile
        else ssl.create_default_context()
    )
    return _SSL_CONTEXT


# Microsoft Teams Desktop public client -- pre-approved in M365 tenants.
# The token inherits all pre-authorized scopes (Mail, Calendar, People, etc.)
# automatically from the app registration, so only narrow scopes are requested.
DEFAULT_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
DEFAULT_SCOPES = "Files.ReadWrite.All Sites.ReadWrite.All offline_access"
TOKEN_FILE = Path.home() / ".config" / "microsoft-graph" / "token.json"


class GraphClient:
    """Microsoft Graph API client with automatic token management."""

    def __init__(self) -> None:
        self._access_token = ""
        self._refresh_token = ""
        self._expires_at = 0.0
        self._client_id = DEFAULT_CLIENT_ID
        self._tenant_id = ""
        self._load_token()

    def _load_token(self) -> None:
        if TOKEN_FILE.exists():
            try:
                data = json.loads(TOKEN_FILE.read_text())
                self._refresh_token = data.get("refresh_token", "")
                self._client_id = data.get("client_id", DEFAULT_CLIENT_ID)
                self._tenant_id = data.get("tenant_id", "")
                self._access_token = data.get("access_token", "")
                self._expires_at = data.get("expires_at", 0.0)
            except (json.JSONDecodeError, KeyError):
                pass
        env_token = os.environ.get("MS_ACCESS_TOKEN", "")
        if env_token and not self._access_token:
            self._access_token = env_token.removeprefix("Bearer ").strip()
            self._expires_at = time.time() + 3000

    def _save_token(self) -> None:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps({
            "refresh_token": self._refresh_token,
            "client_id": self._client_id,
            "tenant_id": self._tenant_id,
            "access_token": self._access_token,
            "expires_at": self._expires_at,
        }, indent=2))
        os.chmod(str(TOKEN_FILE), 0o600)

    def _refresh(self) -> str:
        if not self._refresh_token or not self._tenant_id:
            return ""
        try:
            data = urllib.parse.urlencode({
                "client_id": self._client_id,
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "scope": DEFAULT_SCOPES,
            }).encode()
            url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
                d = json.loads(resp.read())
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                print(f"ERROR: TLS verify failed talking to login.microsoftonline.com: {e.reason}", file=sys.stderr)
                return ""
            print(f"WARNING: Token refresh failed: {e}", file=sys.stderr)
            return ""
        except (ssl.SSLError, FileNotFoundError, IsADirectoryError) as e:
            print(f"ERROR: SSL bundle problem when initializing TLS: {e}", file=sys.stderr)
            return ""
        except Exception as e:
            print(f"WARNING: Token refresh failed: {e}", file=sys.stderr)
            return ""

        try:
            self._access_token = d["access_token"]
        except (KeyError, TypeError) as e:
            print(f"WARNING: Token refresh response malformed (no access_token): {e}", file=sys.stderr)
            return ""
        self._expires_at = time.time() + d.get("expires_in", 3600) - 60
        if "refresh_token" in d:
            self._refresh_token = d["refresh_token"]
        try:
            self._save_token()
        except OSError as e:
            print(f"WARNING: Token saved in memory but failed to persist: {e}", file=sys.stderr)
        return self._access_token

    def get_token(self) -> str:
        if self._access_token and time.time() < self._expires_at:
            return self._access_token
        token = self._refresh()
        if token:
            return token
        env_token = os.environ.get("MS_ACCESS_TOKEN", "")
        if env_token:
            return env_token.removeprefix("Bearer ").strip()
        return ""

    def is_authenticated(self) -> bool:
        return bool(self.get_token())

    def start_auth(self, tenant_id: str = "organizations") -> dict[str, str]:
        data = urllib.parse.urlencode({
            "client_id": DEFAULT_CLIENT_ID,
            "scope": DEFAULT_SCOPES,
        }).encode()
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
            d = json.loads(resp.read())
        self._client_id = DEFAULT_CLIENT_ID
        self._tenant_id = tenant_id
        return {
            "message": d["message"], "user_code": d["user_code"],
            "url": d["verification_uri"], "device_code": d["device_code"],
            "expires_in": str(d.get("expires_in", 900)),
        }

    def complete_auth(self, device_code: str) -> dict[str, str]:
        tid = self._tenant_id or "organizations"
        url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
        for _ in range(24):
            data = urllib.parse.urlencode({
                "client_id": self._client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
                    d = json.loads(resp.read())
                self._access_token = d["access_token"]
                self._refresh_token = d.get("refresh_token", "")
                self._expires_at = time.time() + d.get("expires_in", 3600) - 60
                try:
                    payload = d["access_token"].split(".")[1]
                    payload += "=" * (4 - len(payload) % 4)
                    claims = json.loads(base64.b64decode(payload))
                    self._tenant_id = claims.get("tid", tid)
                except Exception:
                    pass
                self._save_token()
                return {"status": "ok", "message": "Authentication successful! Tokens saved.",
                        "token_file": str(TOKEN_FILE), "scopes": d.get("scope", "")}
            except urllib.error.HTTPError as e:
                body = json.loads(e.read())
                err = body.get("error", "")
                if err == "authorization_pending":
                    time.sleep(5)
                    continue
                return {"status": "error", "error": f"{err}: {body.get('error_description', '')[:200]}"}
        return {"status": "error", "error": "Timed out waiting for user sign-in. Run auth again."}

    def _headers(self) -> dict[str, str]:
        token = self.get_token()
        if not token:
            print("ERROR: No valid access token.", file=sys.stderr)
            sys.exit(1)
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{GRAPH_BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:500]
            print(f"ERROR: Graph API {e.code}: {body}", file=sys.stderr)
            sys.exit(1)

    def try_get(self, path: str, params: dict[str, Any] | None = None) -> Any | None:
        """Like get(), but returns None on 4xx instead of exiting. 5xx still exits."""
        url = f"{GRAPH_BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500:
                return None
            body = e.read().decode()[:500]
            print(f"ERROR: Graph API {e.code}: {body}", file=sys.stderr)
            sys.exit(1)

    def get_bytes(self, path: str) -> bytes:
        """Like get(), but returns the raw response body - for downloading
        file content via /drives/{id}/root:/{path}:/content."""
        url = f"{GRAPH_BASE}{path}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=120, context=_ssl_context()) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:500]
            raise RuntimeError(f"Graph API {e.code} downloading {path}: {body}")
