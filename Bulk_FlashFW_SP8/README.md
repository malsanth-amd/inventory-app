# FlashTools Web

A browser-based version of the FlashTools desktop app: refresh pinned
firmware versions from the SP8 BKC Release Confluence page, then bulk-flash
a fleet of SUTs - all from a webpage instead of an installed EXE.

This is a **rewrite of the presentation/execution layer only**. The actual
firmware logic (`flash_system.py`, `flash_fleet.py`, `refresh_recipe_bkc_page_cli.py`,
`sharepoint_fpga.py`, ...) is a vendored copy of the desktop app's scripts
under `flashtools/`, unchanged, invoked as subprocesses exactly like the
desktop app's `flash_gui.py` does.

## What's NOT the same as the desktop app

- **Manual firmware upload works differently.** Section "1b. Manual
  firmware override" lets you upload a one-off BIOS/BMC/FPGA file per
  platform, same as the desktop GUI's Browse button - but since the
  browser and the server are different machines, the file is uploaded
  over HTTP and staged under the server's temp directory
  (`%TEMP%\flashtools-web\uploads\`), not read directly off your local
  disk the way the desktop app does. It's applied ONLY to target rows
  whose platform matches, so a multi-platform batch never gets one
  platform's firmware applied to another's systems - a row's own
  `bmc_file`/`hpm_file`/`bios_file` CSV column (if you set one) still
  always wins over the web form's upload.
- **Two separate logins, don't confuse them:**
  1. **Per-user sign-in** (Microsoft Entra ID / AMD SSO) - this is just to
     reach the webpage itself. Every engineer signs in with their own
     AMD account.
  2. **Service-account login** (the `atlassian` CLI + Microsoft Graph
     token used by the firmware-refresh job) - this is configured ONCE on
     the server itself by whoever administers it, not per end user (end
     users have no shell access to the server to complete a device-code
     sign-in). See "Service-account setup" below.

## 1. Local test run (no real Entra ID credentials needed yet)

```bash
pip install -r requirements.txt
```

```bash
DEV_BYPASS_AUTH=1 BIND_HOST=127.0.0.1 uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 - you're automatically signed in as "Dev User".
`DEV_BYPASS_AUTH` refuses to start if `BIND_HOST` isn't localhost, so this
mode can never accidentally expose an unauthenticated instance on the
network.

## 2. Entra ID (AMD SSO) app registration (one-time, needs AMD IT)

This web app signs users in via a standard OIDC "Authorization Code" flow,
the same identity platform (`login.microsoftonline.com`) the desktop app
already uses for its SharePoint FPGA download - just a normal browser
redirect login this time instead of a device code.

Ask whoever manages AMD's Entra ID / Azure AD tenant to create an **App
Registration** for this app, and give you:

- **Tenant ID**
- **Client ID** (Application ID)
- **Client Secret** (a value, not just the secret's name/ID)
- Set its **Redirect URI** (platform: Web) to:
  `https://<your-server-host>/auth/callback`

Put these into `.env` (copy `.env.example` first):

```
ENTRA_TENANT_ID=...
ENTRA_CLIENT_ID=...
ENTRA_CLIENT_SECRET=...
ENTRA_REDIRECT_URI=https://<your-server-host>/auth/callback
SESSION_SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_urlsafe(32))">
DEV_BYPASS_AUTH=0
BIND_HOST=0.0.0.0
```

Then run without the dev bypass:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**HTTPS is required** for any real deployment (BMC passwords travel
browser -> server) - put this behind a reverse proxy (nginx/IIS/Caddy)
terminating TLS, or terminate TLS at a load balancer in front of it.

## 3. Service-account setup for firmware refresh (one-time, on the server)

The "Refresh firmware from BKC page" button runs the vendored
`refresh_recipe_bkc_page_cli.py`, which needs:

1. The `atlassian` CLI installed and logged in (read-only profile) -
   **on the server itself**, as whichever OS user runs the web app
   process. See the desktop app's `GETTING_STARTED.txt` Section 5 for the
   exact install/login commands (same steps, just run them on this
   machine instead of a laptop). If running in Docker, this means
   `docker exec`-ing into the running container (or a one-off container
   using the same image) to run the login commands once - the
   `flashtools-config` volume in `docker-compose.yml` persists the result
   across restarts.
2. A one-time Microsoft Graph device-code sign-in for the SharePoint FPGA
   download step - same idea: run the vendored
   `python flashtools/refresh_recipe_bkc_page_cli.py --list-only` once by
   hand on the server (or in the container) the first time, follow the
   printed sign-in URL/code, and the resulting token
   (`~/.config/microsoft-graph/token.json`) is then reused silently by
   every future web-triggered refresh.

## 4. Running via Docker

```bash
cp .env.example .env   # fill in real values first
docker compose up --build
```

## 5. Security notes

- BMC passwords are only ever held in server memory for the duration of
  a job - never written to disk or echoed to the live log unredacted
  (`launcher_utils.redact_cmd_for_display`).
- A web form that can trigger real firmware flashes on physical hardware
  is a meaningful blast-radius surface regardless of login - keep this
  server reachable only from AMD's internal network/VPN, not the open
  internet, SSO notwithstanding.
- Every job is scoped to the signed-in user's account ID - one user
  cannot see or stop another user's job.

## Project layout

```
app/            FastAPI application (routes, auth, job runner, templates/static)
flashtools/     vendored copy of the desktop app's backend scripts - do not edit
                here without also considering the original copy at
                "..\New folder\flash_system.py" etc. (kept in sync manually)
```
