import pathlib
import re
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from . import auth, config, scanner
from .db import SessionLocal, init_db
from .models import Result, Scan, ScanLock

BASE_DIR = pathlib.Path(__file__).resolve().parent

app = FastAPI(title="Phishsurf")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.on_event("startup")
def on_startup():
    init_db()
    with SessionLocal() as db:
        lock = db.get(ScanLock, 1)
        if lock is None:
            db.add(ScanLock(id=1, running_scan_id=None))
        else:
            # Crash/redeploy recovery: nothing can actually be "running"
            # right after startup.
            lock.running_scan_id = None
        stuck = db.execute(select(Scan).where(Scan.status == "running")).scalars().all()
        for scan in stuck:
            scan.status = "queued"
        db.commit()
    scanner.process_queue()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if auth.is_authenticated(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login_submit(request: Request, password: str = Form(...)):
    if not config.APP_PASSWORD:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "APP_PASSWORD is not configured on the server."},
            status_code=500,
        )
    if password != config.APP_PASSWORD:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Wrong password."}, status_code=401,
        )
    response = RedirectResponse("/", status_code=303)
    auth.set_auth_cookie(response)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    auth.clear_auth_cookie(response)
    return response


@app.get("/", response_class=HTMLResponse)
def new_scan_form(request: Request):
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("new_scan.html", {
        "request": request,
        "default_days": config.LOOKBACK_DAYS_DEFAULT,
        "default_limit": config.DEFAULT_SCAN_LIMIT,
        "default_candidates": config.DEFAULT_CANDIDATE_LIMIT,
        "candidate_hard_cap": config.CANDIDATE_HARD_CAP,
        "error": None,
    })


@app.post("/scans")
def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    domain: str = Form(...),
    days: Optional[int] = Form(None),
    limit: Optional[int] = Form(None),
    candidates: Optional[int] = Form(None),
):
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)

    clean_domain = domain.strip().lower()
    clean_domain = re.sub(r"^https?://", "", clean_domain).split("/")[0]

    if not clean_domain or "." not in clean_domain or not re.match(r"^[a-z0-9.-]+$", clean_domain):
        return templates.TemplateResponse("new_scan.html", {
            "request": request,
            "default_days": config.LOOKBACK_DAYS_DEFAULT,
            "default_limit": config.DEFAULT_SCAN_LIMIT,
            "default_candidates": config.DEFAULT_CANDIDATE_LIMIT,
            "candidate_hard_cap": config.CANDIDATE_HARD_CAP,
            "error": "Enter a valid domain, e.g. truniagen.com",
        }, status_code=400)

    scan_days = days or config.LOOKBACK_DAYS_DEFAULT
    scan_days = max(1, min(scan_days, 365))

    scan_limit = limit or config.DEFAULT_SCAN_LIMIT
    scan_limit = max(1, min(scan_limit, config.CANDIDATE_HARD_CAP))

    scan_candidate_limit = candidates or config.DEFAULT_CANDIDATE_LIMIT
    scan_candidate_limit = max(1, min(scan_candidate_limit, config.CANDIDATE_HARD_CAP))

    with SessionLocal() as db:
        scan = Scan(
            domain=clean_domain,
            days=scan_days,
            limit=scan_limit,
            candidate_limit=scan_candidate_limit,
            status="queued",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(scanner.enqueue, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}.json")
def scan_json(scan_id: str, request: Request):
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        results = db.execute(
            select(Result).where(Result.scan_id == scan_id).order_by(Result.score.desc())
        ).scalars().all()
        payload = {
            "scan": {
                "id": scan.id,
                "domain": scan.domain,
                "days": scan.days,
                "limit": scan.limit,
                "candidate_limit": scan.candidate_limit,
                "status": scan.status,
                "candidate_count": scan.candidate_count,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "error_message": scan.error_message,
            },
            "results": [
                {
                    "domain": r.candidate_domain,
                    "score": r.score,
                    "label": r.label,
                    "signals": r.signals,
                    "evidence": r.evidence,
                }
                for r in results
            ],
        }
    response = JSONResponse(payload)
    response.headers["Content-Disposition"] = f'attachment; filename="scan-{scan_id}.json"'
    return response


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: str):
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        results = db.execute(
            select(Result).where(Result.scan_id == scan_id).order_by(Result.score.desc())
        ).scalars().all()
        return templates.TemplateResponse("scan_detail.html", {
            "request": request,
            "scan": scan,
            "results": results,
            "auto_refresh": scan.status in ("queued", "running"),
        })


@app.get("/scans", response_class=HTMLResponse)
def scan_history(request: Request):
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)
    with SessionLocal() as db:
        scans = db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(100)).scalars().all()
    return templates.TemplateResponse("scan_history.html", {"request": request, "scans": scans})
