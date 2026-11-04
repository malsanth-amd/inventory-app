"""Environment-driven settings for the FlashTools web app.

Nothing here has a default for a real secret - every secret-shaped value
(ENTRA_CLIENT_SECRET, SESSION_SECRET_KEY) must come from the environment
or the app refuses to start, same spirit as graph_client.py never hard-
coding a token.
"""

import os
import sys
from pathlib import Path

FLASHTOOLS_DIR = Path(__file__).resolve().parent.parent / "flashtools"
RECIPE_PATH = FLASHTOOLS_DIR / "recipe.yaml"
FIRMWARE_DIR = FLASHTOOLS_DIR / "bin" / "firmware"
FLEET_LOG_DIR = FLASHTOOLS_DIR / "fleet_logs"
SYSTEMS_TEMPLATE_PATH = FLASHTOOLS_DIR / "systems_template.csv"

# -- Entra ID (Azure AD) OIDC --------------------------------------------
ENTRA_TENANT_ID = os.environ.get("ENTRA_TENANT_ID", "")
ENTRA_CLIENT_ID = os.environ.get("ENTRA_CLIENT_ID", "")
ENTRA_CLIENT_SECRET = os.environ.get("ENTRA_CLIENT_SECRET", "")
ENTRA_REDIRECT_URI = os.environ.get("ENTRA_REDIRECT_URI", "http://localhost:8000/auth/callback")
ENTRA_AUTHORITY = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}" if ENTRA_TENANT_ID else ""
ENTRA_SCOPES = ["User.Read"]

# -- Session / dev bypass -------------------------------------------------
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "")
DEV_BYPASS_AUTH = os.environ.get("DEV_BYPASS_AUTH", "") == "1"
BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")

if DEV_BYPASS_AUTH and BIND_HOST not in ("127.0.0.1", "localhost", "::1"):
    print(
        "FATAL: DEV_BYPASS_AUTH=1 is only allowed when BIND_HOST is localhost. "
        "Refusing to start with a non-localhost bind address and auth disabled - "
        "this would let anyone on the network run firmware flashes with no login.",
        file=sys.stderr,
    )
    sys.exit(1)

if not SESSION_SECRET_KEY:
    if DEV_BYPASS_AUTH:
        SESSION_SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
    else:
        print(
            "FATAL: SESSION_SECRET_KEY is not set. Generate one (e.g. "
            "`python -c \"import secrets; print(secrets.token_urlsafe(32))\"`) "
            "and set it as an environment variable - never hardcode it.",
            file=sys.stderr,
        )
        sys.exit(1)

if not DEV_BYPASS_AUTH and not (ENTRA_TENANT_ID and ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET):
    print(
        "FATAL: Entra ID is not configured (ENTRA_TENANT_ID / ENTRA_CLIENT_ID / "
        "ENTRA_CLIENT_SECRET). See README.md's 'Entra ID app registration' section, "
        "or set DEV_BYPASS_AUTH=1 with BIND_HOST=127.0.0.1 for local testing only.",
        file=sys.stderr,
    )
    sys.exit(1)
