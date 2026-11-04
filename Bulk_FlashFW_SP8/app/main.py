"""FlashTools Web - FastAPI front-end over the vendored flash_fleet.py /
refresh_recipe_bkc_page_cli.py scripts (see Server/flashtools/).

Run: uvicorn app.main:app --host 127.0.0.1 --port 8000
"""

import csv
import io
import json
import sys
import tempfile
import uuid
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import auth, config
from .jobs import JobManager

sys.path.insert(0, str(config.FLASHTOOLS_DIR))
from launcher_utils import redact_cmd_for_display  # noqa: E402

APP_DIR = Path(__file__).resolve().parent
BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]
FW_COMPONENTS = ["bios", "bmc", "hpm"]

app = FastAPI(title="FlashTools Web")
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET_KEY, same_site="lax")
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
app.include_router(auth.router)

jobs = JobManager()


def _python_exe() -> str:
    return sys.executable


def _script(name: str) -> str:
    return str(config.FLASHTOOLS_DIR / name)


def _load_recipe() -> dict:
    if not config.RECIPE_PATH.is_file():
        return {"firmware": {}}
    return yaml.safe_load(config.RECIPE_PATH.read_text()) or {"firmware": {}}


# -- Pages ----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: dict = Depends(auth.require_login)):
    recipe = _load_recipe()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user, "recipe": recipe.get("firmware", {}), "board_codes": BOARD_CODES},
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if config.DEV_BYPASS_AUTH:
        return RedirectResponse("/auth/start")  # dev bypass: skip the landing page entirely
    return templates.TemplateResponse("login.html", {"request": request})


# -- API: targets CSV template ---------------------------------------------

@app.get("/api/systems-template.csv")
def systems_template(user: dict = Depends(auth.require_login_api)):
    data = config.SYSTEMS_TEMPLATE_PATH.read_text()
    return StreamingResponse(io.StringIO(data), media_type="text/csv",
                              headers={"Content-Disposition": "attachment; filename=systems_template.csv"})


# -- API: jobs --------------------------------------------------------------

@app.post("/api/jobs/refresh")
async def start_refresh_job(user: dict = Depends(auth.require_login_api)):
    cmd = [_python_exe(), "-u", _script("refresh_recipe_bkc_page_cli.py"),
           "--output", str(config.RECIPE_PATH), "--firmware-dir", str(config.FIRMWARE_DIR)]
    job = jobs.start(cmd, owner=user["oid"], kind="refresh")
    return {"job_id": job.id, "cmd_display": " ".join(redact_cmd_for_display(cmd))}


@app.post("/api/jobs/flash")
async def start_flash_job(
    request: Request,
    targets_csv: UploadFile,
    dry_run: bool = True,  # sent as a query param (see app.js) - fine unannotated alongside Form(...) fields below
    bmc_user: str = Form(""),
    bmc_pass: str = Form(""),
    user: dict = Depends(auth.require_login_api),
):
    csv_bytes = await targets_csv.read()
    rows = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8"))))
    if not rows:
        return JSONResponse({"error": "No target systems found in the uploaded CSV."}, status_code=400)

    # flash_fleet.py has no top-level --bmc-user/--bmc-pass flags - those are
    # per-row CSV columns only (a row's own value always wins). The web
    # form's credential fields are a fallback applied to any row that left
    # them blank, so fill them in here rather than passing them as CLI args.
    fieldnames = list(rows[0].keys())
    for col in ("bmc_user", "bmc_pass", "bmc_file", "bmc_version", "hpm_file", "hpm_version", "bios_file", "bios_version"):
        if col not in fieldnames:
            fieldnames.append(col)
    for row in rows:
        if bmc_user and not row.get("bmc_user"):
            row["bmc_user"] = bmc_user
        if bmc_pass and not row.get("bmc_pass"):
            row["bmc_pass"] = bmc_pass

    # Manual firmware override (the web equivalent of the desktop GUI's per-
    # platform Browse buttons): the form carries optional file fields named
    # fw_<platform>_<component> (bios/bmc/hpm) and fw_<platform>_<component>_version.
    # Each uploaded file is staged to disk, then applied ONLY to rows whose
    # platform matches - same per-row bmc_file/hpm_file/bios_file CSV columns
    # flash_fleet.py already supports, so a multi-platform batch never leaks
    # one platform's firmware onto another's systems (mirrors flash_gui.py's
    # own "MULTI-PLATFORM BATCHES" design).
    form = await request.form()
    job_upload_dir = Path(tempfile.gettempdir()) / "flashtools-web" / "uploads" / f"{user['oid']}-{uuid.uuid4().hex[:8]}"
    overrides = {}  # platform -> {component: {"file": staged_path, "version": str|None}}
    for board in BOARD_CODES:
        for component in FW_COMPONENTS:
            upload = form.get(f"fw_{board}_{component}")
            if upload is None or not getattr(upload, "filename", ""):
                continue
            dest_dir = job_upload_dir / board
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / upload.filename
            dest.write_bytes(await upload.read())
            version = (form.get(f"fw_{board}_{component}_version") or "").strip() or None
            overrides.setdefault(board, {})[component] = {"file": str(dest), "version": version}

    for row in rows:
        board_overrides = overrides.get(row.get("platform", ""))
        if not board_overrides:
            continue
        for component, info in board_overrides.items():
            file_col, ver_col = f"{component}_file", f"{component}_version"
            if not row.get(file_col):
                row[file_col] = info["file"]
                if info["version"]:
                    row[ver_col] = info["version"]

    tmp_dir = Path(tempfile.gettempdir()) / "flashtools-web"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_csv = tmp_dir / f"targets-{user['oid']}-{len(rows)}.csv"
    with open(tmp_csv, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # flash_fleet.py has no --firmware-dir/--recipe flags of its own - it
    # dispatches to flash_system.py per system, which already defaults both
    # to paths relative to Server/flashtools/ (see launcher_utils.app_dir()).
    cmd = [_python_exe(), "-u", _script("flash_fleet.py"), str(tmp_csv),
           "--log-dir", str(config.FLEET_LOG_DIR)]
    if dry_run:
        cmd += ["--dry-run"]
    else:
        cmd += ["-y"]

    job = jobs.start(cmd, owner=user["oid"], kind="flash")
    return {"job_id": job.id, "cmd_display": " ".join(redact_cmd_for_display(cmd))}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, user: dict = Depends(auth.require_login_api)):
    job = jobs.get(job_id, owner=user["oid"])
    if job is None:
        return JSONResponse({"error": "Job not found."}, status_code=404)
    return {
        "id": job.id, "kind": job.kind, "done": job.done, "exit_code": job.exit_code,
        "statuses": job.statuses, "line_count": len(job.lines),
    }


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str, user: dict = Depends(auth.require_login_api)):
    ok = jobs.stop(job_id, owner=user["oid"])
    return {"stopped": ok}


@app.get("/api/jobs/{job_id}/stream")
async def stream_job(job_id: str, user: dict = Depends(auth.require_login_api)):
    job = jobs.get(job_id, owner=user["oid"])
    if job is None:
        return JSONResponse({"error": "Job not found."}, status_code=404)

    async def event_gen():
        q = job.subscribe()
        while True:
            line = await q.get()
            if line is None:
                payload = {"done": True, "exit_code": job.exit_code, "statuses": job.statuses}
                yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                break
            yield f"data: {json.dumps({'line': line, 'statuses': job.statuses})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")
