"""
settings.py -- Application preferences, theme, autostart, proxy, and log sanitizer settings.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from ghostdrive.web.state import state

router = APIRouter(prefix="/api/settings", tags=["settings"])

class SettingsUpdateModel(BaseModel):
    theme: str = "dark"
    accent_color: str = "#c4f56a"
    autostart: bool = False
    desktop_notifications: bool = True
    log_level: str = "INFO"
    proxy_type: str = "none"
    proxy_host: str = ""
    proxy_port: int = 0

@router.get("/")
def get_settings() -> dict:
    return state.settings

@router.post("/")
def update_settings(req: SettingsUpdateModel) -> dict:
    state.settings.update(req.model_dump())

    try:
        from ghostdrive.platform.autostart import set_autostart
        set_autostart(bool(req.autostart))
    except Exception as exc:
        import logging
        logging.getLogger("ghostdrive.web.settings").warning("Autostart update failed: %s", exc)

    try:
        state.persist_settings()
    except Exception as exc:
        import logging
        logging.getLogger("ghostdrive.web.settings").warning("Could not persist settings: %s", exc)

    return {
        "status": "success",
        "settings": state.settings,
        "message": "Application settings saved."
    }
