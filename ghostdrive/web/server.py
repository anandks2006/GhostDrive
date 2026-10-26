"""
server.py -- Main FastAPI application server launcher for GhostDrive Web Interface.
"""

import sys
import signal
import logging
import asyncio
import webbrowser
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn

from ghostdrive.web.state import state
from ghostdrive.web.routes import (
    preflight,
    auth,
    files,
    backends,
    analytics,
    resilience,
    hostility,
    smart,
    secrets,
    settings,
    sharing,
    telemetry,
    protection,
    recovery,
    portable,
    monitoring,
    sync,
    update,
)
from ghostdrive.services import protection as protection_service
from ghostdrive.services.alerts import start_alerts_scheduler, stop_alerts_scheduler
from ghostdrive.services.restore_drills import (
    start_drill_scheduler,
    stop_drill_scheduler,
)
from ghostdrive.utils.log_sanitizer import SanitizedFormatter

# Setup logging
log_file_path = Path("ghostdrive.log")
file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
file_handler.setFormatter(SanitizedFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(SanitizedFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    handlers=[stream_handler, file_handler]
)
logger = logging.getLogger("ghostdrive_web")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("GhostDrive Web Server started.")
    protection_service.start_watcher()
    # Both schedulers are double-start no-ops and tolerate a locked vault.
    start_drill_scheduler()
    start_alerts_scheduler()
    yield
    logger.info("GhostDrive Web Server shutting down...")
    stop_drill_scheduler()
    stop_alerts_scheduler()
    protection_service.stop_watcher()
    state.clean_shutdown()

app = FastAPI(
    title="GhostDrive Web App",
    description="Encrypted, Redundant, Multi-Backend Personal Cloud Drive",
    version="0.1.0-alpha",
    lifespan=lifespan,
)

# Include API Routers
app.include_router(preflight.router)
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(backends.router)
app.include_router(analytics.router)
app.include_router(resilience.router)
app.include_router(hostility.router)
app.include_router(smart.router)
app.include_router(secrets.router)
app.include_router(settings.router)
app.include_router(sharing.router)
app.include_router(sharing.public_router)
app.include_router(telemetry.router)
app.include_router(protection.router)
app.include_router(recovery.router)
app.include_router(portable.router)
app.include_router(monitoring.router)
app.include_router(sync.router)
app.include_router(update.router)

# Mount Static Assets
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return HTMLResponse("<h2>GhostDrive Web App loading...</h2>")

@app.get("/manifest.webmanifest")
async def serve_manifest():
    """Serve the PWA manifest with the correct MIME type for installability."""
    manifest_path = static_dir / "manifest.webmanifest"
    if manifest_path.exists():
        return FileResponse(str(manifest_path), media_type="application/manifest+json")
    return HTMLResponse("<h2>Manifest not available.</h2>", status_code=404)

@app.get("/serviceworker.js")
async def serve_service_worker():
    """Serve the service worker from the root scope (a /static/ worker could only claim /static/*)."""
    worker_path = static_dir / "serviceworker.js"
    if worker_path.exists():
        return FileResponse(str(worker_path), media_type="text/javascript")
    return HTMLResponse("<h2>Service worker not available.</h2>", status_code=404)

def find_available_port(start_port: int = 8000, max_attempts: int = 20) -> int:
    import socket
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return start_port

def main():
    """CLI entrypoint launcher for `ghostdrive` executable."""
    host = "127.0.0.1"
    port = find_available_port(8000)
    url = f"http://{host}:{port}"
    logger.info(f"Starting GhostDrive Web Server at {url}")
    
    def open_browser():
        webbrowser.open(url)

    import threading
    threading.Timer(1.0, open_browser).start()

    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
