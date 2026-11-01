"""MailGuard1 FastAPI application entry point."""

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.database import init_db, SessionLocal
from backend.services.scan_service import seed_initial_samples_if_empty
from backend.routes import health, scan, history, dashboard, auth, gmail

# Setup logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mailguard")

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Initializing MailGuard database and models...")
    init_db()
    yield
    logger.info("Shutting down MailGuard backend.")


app = FastAPI(
    title=settings.APP_NAME,
    description="MailGuard1 Security Intelligence Backend - Spam, Phishing, and Spoofing Detection",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS
origins = settings.cors_origin_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health.router)
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(dashboard.router)
app.include_router(auth.router)
app.include_router(gmail.router)


@app.get("/api", tags=["API Root"])
async def get_api_root():
    """API overview and quick navigation."""
    return {
        "service": settings.APP_NAME,
        "status": "online",
        "documentation": "/docs",
        "endpoints": {
            "health": "/api/health",
            "auth_me": "/api/auth/me",
            "auth_login": "/api/auth/google/login",
            "auth_logout": "/api/auth/logout",
            "gmail_status": "/api/gmail/status",
            "gmail_connect": "/api/gmail/connect",
            "gmail_scan": "/api/gmail/scan",
            "gmail_disconnect": "/api/gmail/disconnect",
            "scan": "/api/scan",
            "receive_sample": "/api/scan/receive",
            "history": "/api/history",
            "dashboard_stats": "/api/dashboard/stats",
        },
    }


NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


# Serve original frontend at root URL
@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the existing MailGuard frontend without modifications."""
    html_file = BASE_DIR / "MailGuard (4).html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html", headers=NO_CACHE_HEADERS)
    return {"message": "MailGuard1 API running. Please place MailGuard (4).html in root directory."}


# Serve dedicated login and signup pages
@app.get("/login", include_in_schema=False)
async def serve_login():
    """Serve the dedicated login page matching MailGuard visual design system."""
    login_file = BASE_DIR / "login.html"
    if login_file.exists():
        return FileResponse(login_file, media_type="text/html", headers=NO_CACHE_HEADERS)
    return RedirectResponse(url="/")


@app.get("/signup", include_in_schema=False)
async def serve_signup():
    """Serve the dedicated signup page matching MailGuard visual design system."""
    signup_file = BASE_DIR / "signup.html"
    if signup_file.exists():
        return FileResponse(signup_file, media_type="text/html", headers=NO_CACHE_HEADERS)
    return RedirectResponse(url="/")


# Serve companion integration JS
@app.get("/mailguard-api.js", include_in_schema=False)
async def serve_integration_js():
    js_file = BASE_DIR / "mailguard-api.js"
    if js_file.exists():
        return FileResponse(js_file, media_type="application/javascript", headers=NO_CACHE_HEADERS)
    return {"error": "mailguard-api.js not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
