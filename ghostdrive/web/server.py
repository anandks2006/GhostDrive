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
    smart,
    secrets,
    settings,
    sharing,
    telemetry,
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
    yield
    logger.info("GhostDrive Web Server shutting down...")
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
app.include_router(smart.router)
app.include_router(secrets.router)
app.include_router(settings.router)
app.include_router(sharing.router)
app.include_router(telemetry.router)

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
